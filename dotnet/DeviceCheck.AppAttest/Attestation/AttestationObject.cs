using System.Security.Cryptography.X509Certificates;
using DeviceCheck.AppAttest.Cbor;

namespace DeviceCheck.AppAttest.Attestation;

internal class AttestationObject
{
    [CborProperty("fmt")]
    public string Format { get; set; } = default!;
    [CborProperty("attStmt")]
    public StatementFormat AttestationStatement { get; set; } = default!;
    [CborProperty("authData")]
    public byte[] AuthData { get; set; } = default!;

    public class StatementFormat
    {
        [CborProperty("x5c")]
        public byte[][] Certificates { get; set; } = default!;
        [CborProperty("receipt")]
        public byte[] Receipt { get; set; } = default!;

        public IEnumerable<X509Certificate2> GetCertificates()
        {
            foreach(var certData in Certificates)
            {
                yield return new X509Certificate2(certData);
            }
        }
    }
}
