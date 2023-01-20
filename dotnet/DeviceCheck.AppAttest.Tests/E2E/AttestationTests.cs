using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Policy;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Web;
using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Cache;
using DeviceCheck.AppAttest.Extensions;
using DeviceCheck.AppAttest.Tests.E2E.Utility;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DeviceCheck.AppAttest.Tests.E2E;

public class AttestationTests : IClassFixture<StartupWebApplicationFactory<TestStartup>>
{
    private readonly StartupWebApplicationFactory<TestStartup> _factory;
    private readonly FakeAttestService _attestationService;

    public AttestationTests(StartupWebApplicationFactory<TestStartup> factory)
    {
        _factory = factory;
        _attestationService = new FakeAttestService();
    }

    [Fact]
    public async Task WhenRequestUnauthorized_ResponseShouldBeUnauthorized()
    {
        // arrange
        var client = _factory.CreateClient();
        var correlationId = Guid.NewGuid().ToString();
        client.DefaultRequestHeaders.Add("X-Correlation-ID", correlationId);
        
        // act
        var response = await client.GetAsync("/test");
        var authChallenge = response.Headers
            .GetValues("WWW-Authenticate")
            .Select(AuthenticationHeaderValue.Parse)
            .Single();

        var parameters = authChallenge.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        // assert
        Assert.Equal(AppAttestDefaults.AuthenticationScheme, authChallenge.Scheme);
        Assert.True(parameters?.ContainsKey("url"));
        Assert.True(parameters?.ContainsKey("challenge"));
    }

    [Fact]
    public async Task WhenRequestUnauthorized_ResponseShouldBeChallenge()
    {
        // arrange
        var client = _factory.CreateClient();
        var correlationId = Guid.NewGuid().ToString();
        client.DefaultRequestHeaders.Add("X-Correlation-ID", correlationId);

        // act
        var response = await client.GetAsync("/test");
        var authChallenge = response.Headers
            .GetValues("WWW-Authenticate")
            .Select(AuthenticationHeaderValue.Parse)
            .Single();

        var parameters = authChallenge.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        var challenge = Convert.FromBase64String(parameters?["challenge"] ?? "");

        // assert
        var options = _factory.Services.GetRequiredService<IOptions<AppAttestAuthOptions>>().Value;
        Assert.Equal(options.ChallengeLength, challenge.Length);
    }

    [Fact]
    public async Task WhenRequestUnauthorized_ResponseLocationShouldBeAttestationPath()
    {
        // arrange
        var client = _factory.CreateClient();
        var correlationId = Guid.NewGuid().ToString();
        client.DefaultRequestHeaders.Add("X-Correlation-ID", correlationId);

        // act
        var response = await client.GetAsync("/test");
        var authChallenge = response.Headers
            .GetValues("WWW-Authenticate")
            .Select(AuthenticationHeaderValue.Parse)
            .Single();

        var parameters = authChallenge.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        // assert
        var options = _factory.Services.GetRequiredService<IOptions<AppAttestAuthOptions>>().Value;
        Assert.Equal("http://localhost" + options.AttestationPath, parameters?["url"]);
    }

    [Fact]
    public async Task WhenValidAttestation_ResponseShouldBeNoContent()
    {
        // arrange
        var client = _factory.CreateClient();
        var correlationId = Guid.NewGuid().ToString();
        client.DefaultRequestHeaders.Add("X-Correlation-ID", correlationId);

        var challengeResponse = await client.GetAsync("/test");
        var authChallenge = challengeResponse.Headers
            .GetValues("WWW-Authenticate")
            .Select(AuthenticationHeaderValue.Parse)
            .Single();

        var parameters = authChallenge.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        var challenge = Convert.FromBase64String(parameters?["challenge"] ?? "");
        var attestPath = parameters?["url"];

        var key = RSA.Create();
        var keyId = Convert.ToBase64String(SHA256.HashData(key.ExportRSAPublicKey()));
        var (attestationData, credCert) = await _attestationService.CreateAttestationStatement(
            challenge,
            TestStartup.AppId,
            key
        );

        var attestationContent = new ByteArrayContent(attestationData);

        var attestationMessage = new HttpRequestMessage(HttpMethod.Post, attestPath);
        attestationMessage.Headers.Authorization = new AuthenticationHeaderValue(
            AppAttestDefaults.AuthenticationScheme,
            $"key-id={HttpUtility.UrlEncode(keyId)} corr-id={HttpUtility.UrlEncode(correlationId)} attest={HttpUtility.UrlEncode(Convert.ToBase64String(attestationData))}"
        );

        // act
        var attestationResponse = await client.SendAsync(attestationMessage);

        // assert
        Assert.Equal(HttpStatusCode.NoContent, attestationResponse.StatusCode);
    }

    [Fact]
    public async Task WhenCompletedAttestation_ResourceResponseShouldBeExpected()
    {
        // arrange
        var client = _factory.CreateClient();
        var correlationId = Guid.NewGuid().ToString();

        var requestContent = JsonContent.Create(new { Value = "test" });
        requestContent.Headers.Add("X-Correlation-ID", correlationId);

        var challengeResponse = await client.PostAsync("/test", requestContent);
        var authChallenge = challengeResponse.Headers
            .GetValues("WWW-Authenticate")
            .Select(AuthenticationHeaderValue.Parse)
            .Single();

        var parameters = authChallenge.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        var challenge = Convert.FromBase64String(parameters?["challenge"] ?? "");
        var attestPath = parameters?["url"];

        var key = RSA.Create();
        var keyId = Convert.ToBase64String(SHA256.HashData(key.ExportRSAPublicKey()));
        var (attestationData, credCert) = await _attestationService.CreateAttestationStatement(
            challenge,
            TestStartup.AppId,
            key
        );

        var attestationMessage = new HttpRequestMessage(HttpMethod.Post, attestPath);
        attestationMessage.Headers.Authorization = new AuthenticationHeaderValue(
            AppAttestDefaults.AuthenticationScheme,
            $"key-id={HttpUtility.UrlEncode(keyId)} corr-id={HttpUtility.UrlEncode(correlationId)} attest={HttpUtility.UrlEncode(Convert.ToBase64String(attestationData))}"
        );

        await client.SendAsync(attestationMessage);

        var assertionStatement = await _attestationService.CreateAssertion(key, credCert, requestContent, TestStartup.AppId);

        
        var resourceMessage = new HttpRequestMessage(HttpMethod.Post, "/test");
        resourceMessage.Headers.Authorization = new AuthenticationHeaderValue(
            AppAttestDefaults.AuthenticationScheme,
            $"key-id={HttpUtility.UrlEncode(keyId)} assert={HttpUtility.UrlEncode(Convert.ToBase64String(assertionStatement))}"
        );

        resourceMessage.Content = requestContent;

        // act
        var resourceResponse = await client.SendAsync(resourceMessage);

        // assert
        Assert.Equal(HttpStatusCode.OK, resourceResponse.StatusCode);
        Assert.Equal("test", await resourceResponse.Content.ReadAsStringAsync());
    }
}

internal class NoHttpContent : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        return base.SerializeToStreamAsync(stream, context, default);
    }

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return true;
    }
}