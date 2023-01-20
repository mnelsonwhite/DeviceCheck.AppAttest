using System.Security.Cryptography.X509Certificates;
using DeviceCheck.AppAttest.Cache;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace DeviceCheck.AppAttest.Attestation;

public class AppAttestAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Length of the challenge generated
    /// </summary>
    public int ChallengeLength { get; set; }
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
    public TimeSpan AttestationDataTtl { get; set; }
    /// <summary>
    /// The persisted attestation result ID prefix
    /// </summary>
    public string AttestationDataKeyPrefix { get; set; }
    /// <summary>
    /// The base64 PEM encoded root certificate for attestation
    /// certificate chain validation
    /// </summary>
    public string? RootCertificatePem { get; set; }
    /// <summary>
    /// The APP ID which is being attested.
    /// format: "<team id>.<bundle identifier>"
    /// </summary>
    public string? AppId { get; set; }
    public string AttestationPath { get; set; }

    public AppAttestAuthOptions()
    {
        ChallengeLength = 64;
        ChallengeTtl = TimeSpan.FromMinutes(1);
        AttestationDataTtl = TimeSpan.FromDays(30);
        ChallengeKeyPrefix = "appattest:challenge:";
        AttestationDataKeyPrefix = "appattest:attest:";
        AttestationPath = "/attestation";
    }

    /// <summary>
    /// The RootCertificatePem decoded into a X509 certificate structure
    /// </summary>
    /// <returns></returns>
    public X509Certificate2 GetRootCertificate()
        => X509Certificate2.CreateFromPem(RootCertificatePem);
}