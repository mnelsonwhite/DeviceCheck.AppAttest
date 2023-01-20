using System.Net;
using System.Net.Http.Headers;
using System.Web;
using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Cache;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DeviceCheck.AppAttest.Extensions;

public static class WebApplicationExtensions
{
    public static void AddAppAttest(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<AppAttestAuthOptions>>();
        var service = app.Services.GetRequiredService<IAppAttestService>();
        var cache = app.Services.GetRequiredService<ICacheProvider>();
        app.MapPost(options.Value.AttestationPath, context => Attestation(service, cache, context, options));
    }

    public static void AddAppAttest(this IApplicationBuilder builder)
    {
        var options = builder.ApplicationServices.GetRequiredService<IOptions<AppAttestAuthOptions>>();
        builder.Map(options.Value.AttestationPath, AttestationBuilder);
    }

    private static void AttestationBuilder(IApplicationBuilder builder)
    {
        var provider = builder.ApplicationServices;
        var options = provider.GetRequiredService<IOptions<AppAttestAuthOptions>>();
        var service = provider.GetRequiredService<IAppAttestService>();
        var cache = provider.GetRequiredService<ICacheProvider>();

        builder.Run(context => Attestation(service, cache, context, options));
    }

    private static async Task Attestation(
        IAppAttestService service,
        ICacheProvider cache,
        HttpContext context,
        IOptions<AppAttestAuthOptions> options)
    {
        var optionsValue = options.Value;

        if (!context.Request.Headers.TryGetValue("Authorization", out var authorizationHeader)
            || !authorizationHeader
                .Select(AuthenticationHeaderValue.Parse)
                .Where(v => v.Scheme == AppAttestDefaults.AuthenticationScheme)
                .TryGetFirst(out var authorizationHeaderValue)
            || authorizationHeaderValue is null
        )
        {
            throw new AppAttestException("Missing Authorization header");
        }

        var parameters = authorizationHeaderValue.Parameter?.Split(' ')
            .Select(NameValueHeaderValue.Parse)
            .ToDictionary(v => v.Name, v => HttpUtility.UrlDecode(v.Value));

        var keyId = parameters?["key-id"];
        if (keyId is null)
        {
            throw new AppAttestException("Missing key-id parameter on Authorization header");
        }

        var correlationId = parameters?["corr-id"];
        if (correlationId is null)
        {
            throw new AppAttestException("Missing corr-id parameter on Authorization header");
        }

        var attestation = parameters?["attest"];
        if (attestation is null)
        {
            throw new AppAttestException("Missing attest parameter on Authorization header");
        }

        // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
        var challenge = await cache.Get<byte[]>(optionsValue.ChallengeKeyPrefix + correlationId);
        if (challenge is null)
        {
            throw new AppAttestException("No challenge data found for provided corr-id");
        }

        try
        {
            var authResult = await service.ValidateAttestation(
                Convert.FromBase64String(attestation),
                challenge,
                keyId,
                optionsValue.AppId ?? throw new Exception(),
                optionsValue.GetRootCertificate()
            );

            await cache.Set(
                optionsValue.AttestationDataKeyPrefix + keyId,
                authResult,
                optionsValue.AttestationDataTtl
            );

            context.Response.StatusCode = (int)HttpStatusCode.NoContent;
        }
        catch (AttestationException exception)
        {
            throw new AppAttestException("Attestation failed: " + exception.Message);
        }
        finally
        {
            await cache.Remove(optionsValue.ChallengeKeyPrefix + correlationId);
        }
    }
}