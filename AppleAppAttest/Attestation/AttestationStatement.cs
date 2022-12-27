using System.Security.Cryptography.X509Certificates;

namespace AppleAppAttest.Attestation;

internal class AttestationStatement
{
    public string fmt { get; set; } = default!;
    public StatementFormat attStmt { get; set; } = default!;
    public byte[] authData { get; set; } = default!;

    public class StatementFormat
    {
        public byte[][] x5c { get; set; } = default!;
        public byte[] receipt { get; set; } = default!;

        public IEnumerable<X509Certificate2> GetCertificates()
        {
            foreach(var certData in x5c)
            {
                yield return new X509Certificate2(certData);
            }
        }
    }
}
