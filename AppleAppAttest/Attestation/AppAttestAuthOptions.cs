using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;

namespace AppleAppAttest.Attestation;

public class AppAttestAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Length of the challenge generated
    /// </summary>
    public int ChallengeLegnth { get; set; }
    /// <summary>
    /// How long the challenge is persisted for
    /// </summary>
    public TimeSpan ChallengeTtl { get; set; }
    /// <summary>
    /// The persisted challenge ID prefix
    /// </summary>
    public string ChallengeKeyPrefix { get; set; }
    /// <summary>
    /// How long the attestation result is persisted for
    /// </summary>
    public TimeSpan AttestationTtl { get; set; }
    /// <summary>
    /// The persisted attestation result ID prefix
    /// </summary>
    public string AttestationKeyPrefix { get; set; }
    /// <summary>
    /// The base64 PEM encoded root certificate for attestation
    /// certificate chain validation
    /// </summary>
    public string RootCertificatePem { get; set; }
    /// <summary>
    /// The APP ID which is being attested.
    /// format: "<team id>.<bundle identifier>"
    /// </summary>
    public string AppId { get; set; }
    /// <summary>
    /// The correlation ID header for correlated the challenge and attestation
    /// </summary>
    public string CorrelationIdHeader { get; set; }
    /// <summary>
    /// The Key ID header for providing the Key ID for attestation and assertions
    /// </summary>
    public string KeyIdHeader { get; set; }

    public AppAttestAuthOptions()
    {
        ChallengeLegnth = 64;
        ChallengeTtl = TimeSpan.FromMinutes(1);
        AttestationTtl = TimeSpan.FromDays(30);
        ChallengeKeyPrefix = "attest:challenge:";
        AttestationKeyPrefix = "attest:key:";
        RootCertificatePem = "";
        AppId = "";

        CorrelationIdHeader = "X-Correlation-ID";
        KeyIdHeader = "X-Key-ID";
    }

    /// <summary>
    /// The RootCertificatePem decoded into a X509 certificate structure
    /// </summary>
    /// <returns></returns>
    public X509Certificate2 GetRootCertificate()
        => X509Certificate2.CreateFromPem(RootCertificatePem);
}
