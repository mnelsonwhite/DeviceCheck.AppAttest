using System.Security.Cryptography.X509Certificates;

namespace AppleAppAttest.Attestation;

public interface IAttestationService
{
    byte[] GetChallenge(int length);
    Task<AttestationResult> ValidateAttestation(
        Stream attestationData,
        X509Certificate2 rootCertificate,
        byte[] challenge,
        string keyId,
        string appId
    );
}
