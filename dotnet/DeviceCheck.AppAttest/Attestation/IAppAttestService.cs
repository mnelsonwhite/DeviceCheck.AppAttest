using System.Security.Cryptography.X509Certificates;

namespace DeviceCheck.AppAttest.Attestation;

public interface IAppAttestService
{
    byte[] GetChallenge(int length);
    Task<AttestationData> ValidateAttestation(
        byte[] attestationData,
        byte[] challenge,
        string keyId,
        string appId,
        X509Certificate2 rootCertificate
    );

    Task<AttestationData> ValidateAssertion(
        AttestationData attestationResult,
        Stream clientDataStream,
        byte[] assertionStatement,
        string appId
    );
}
