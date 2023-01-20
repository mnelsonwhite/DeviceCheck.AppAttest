using System.Security.Cryptography.X509Certificates;

namespace DeviceCheck.AppAttest.Attestation;

public record AttestationData(byte[] CredCertData, byte[] Receipt, byte[] Challenge, uint SignCount = 0)
{
    public X509Certificate2 GetCredCert() => new X509Certificate2(CredCertData);
};
