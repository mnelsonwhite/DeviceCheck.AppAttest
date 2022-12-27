using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AppleAppAttest.Attestation;
using AppleAppAttest.Cache;
using AppleAppAttest.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AppleAppAttest.Attestation;

public class AppAttestAuthHandler : AuthenticationHandler<AppAttestAuthOptions>
{
    private readonly IAttestationService _attestationService;
    private readonly ICacheProvider _cache;

    public AppAttestAuthHandler(
        IOptionsMonitor<AppAttestAuthOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IAttestationService attestationService,
        ICacheProvider cache) : base(options, logger, encoder, clock)
    {
        _attestationService = attestationService;
        _cache = cache;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.CorrelationIdHeader, out var correlationIdHeader)
            || !correlationIdHeader.TryGetFirst(out var correlationId)
            || correlationId is null
        ) return AuthenticateResult.NoResult();

        if (!Request.Headers.TryGetValue(Options.CorrelationIdHeader, out var keyIdHeader)
            || !keyIdHeader.TryGetFirst(out var keyId)
            || keyId is null
        ) return AuthenticateResult.NoResult();

        // https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
        var challenge = await _cache.Get<byte[]>(Options.ChallengeKeyPrefix + correlationId);
        if (challenge is null) return AuthenticateResult.NoResult();

        try {
            var authResult = await _attestationService.ValidateAttestation(
                Request.Body,
                Options.GetRootCertificate(),
                challenge,
                keyId,
                Options.AppId
            );

            await _cache.Set(
                Options.AttestationKeyPrefix + keyId,
                authResult,
                Options.AttestationTtl
            );

            var identity = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.NameIdentifier, keyId)
            });
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
            await _cache.Remove(Options.ChallengeKeyPrefix + correlationId);
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Request.Headers.TryGetValue(AttestAuthHeaders.CorrelationId, out var correlationIdHeader)
            || !correlationIdHeader.TryGetFirst(out var correlationId)
            || correlationId is null)
        {
            Response.StatusCode = (int)HttpStatusCode.BadRequest;
            return;
        }

        var challenge = _attestationService.GetChallenge(Options.ChallengeLegnth);
        using var stream = new MemoryStream(challenge);

        await _cache.Set(
            Options.ChallengeKeyPrefix + correlationId,
            challenge,
            Options.ChallengeTtl
        );

        Response.Body = stream;
        await base.HandleChallengeAsync(properties);
    }
}


