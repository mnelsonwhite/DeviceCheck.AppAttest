using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Web;
using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Cache;
using DeviceCheck.AppAttest.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DeviceCheck.AppAttest.Attestation;

public class AppAttestAuthHandler : AuthenticationHandler<AppAttestAuthOptions>
{
    private readonly IAppAttestService _attestationService;
    private readonly ICacheProvider _cache;

    public AppAttestAuthHandler(
        IOptionsMonitor<AppAttestAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IAppAttestService attestationService,
        ICacheProvider cache) : base(options, logger, encoder, clock)
    {
        _attestationService = attestationService;
        _cache = cache;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader)
            || !authorizationHeader
                .Select(AuthenticationHeaderValue.Parse)
                .Where(v => v.Scheme == AppAttestDefaults.AuthenticationScheme)
                .TryGetFirst(out var authorizationHeaderValue)
            || authorizationHeaderValue is null
        ) return AuthenticateResult.NoResult();

        var parameters = authorizationHeaderValue.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        var keyId = parameters?.GetValueOrDefault("key-id");
        if (keyId is null) return AuthenticateResult.NoResult();

        var assertion = parameters?.GetValueOrDefault("assert");
        if (assertion is null) return AuthenticateResult.NoResult();

        var attestationData = await _cache.Get<AttestationData>(Options.AttestationDataKeyPrefix + keyId);
        if (attestationData is null) return AuthenticateResult.Fail(
            new AssertionException("Missing attestion data")
        );

        var stream = new MemoryStream();
        await Request.Body.CopyToAsync(stream);
        stream.Seek(0, SeekOrigin.Begin);

        try
        {
            await _attestationService.ValidateAssertion(
                attestationData,
                stream,
                Convert.FromBase64String(assertion),
                Options.AppId ?? throw new AttestationException("Missing App ID")
            );

            var identity = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.Name, keyId)
            }, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var authProperties = new AuthenticationProperties();
            var authTicket = new AuthenticationTicket(
                principal,
                authProperties,
                Scheme.Name
            );

            return AuthenticateResult.Success(authTicket);
        }
        catch(Exception exception)
        {
            return AuthenticateResult.Fail(exception);
        }
        finally
        {
            stream.Seek(0, SeekOrigin.Begin);
            Request.Body = stream;
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Request.Headers.TryGetValue("X-Correlation-ID", out var correlationIdHeader)
            || !correlationIdHeader.TryGetFirst(out var correlationId)
            || correlationId is null)
        {
            Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            return;
        }

        var challenge = _attestationService.GetChallenge(Options.ChallengeLength);
        await _cache.Set(
            Options.ChallengeKeyPrefix + correlationId,
            challenge,
            Options.ChallengeTtl
        );


        //new Uri(Request.Host.Value, Options.AttestationPath);
        
        var uri = new Uri(new Uri(Request.GetEncodedUrl()), Options.AttestationPath);

        Response.Headers["WWW-Authenticate"]
            = $"{AppAttestDefaults.AuthenticationScheme} " +
            $"url={HttpUtility.UrlEncode(uri.ToString())} " +
            $"challenge={HttpUtility.UrlEncode(Convert.ToBase64String(challenge))}";

        await base.HandleChallengeAsync(properties);
    }
}
