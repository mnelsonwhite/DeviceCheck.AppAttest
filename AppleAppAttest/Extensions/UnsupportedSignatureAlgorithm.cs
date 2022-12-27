using System.Security.Cryptography;

namespace AppleAppAttest.Extensions;

internal class UnsupportedSignatureAlgorithm : NotSupportedException
{
    public UnsupportedSignatureAlgorithm(Oid signatureAlgorithm)
        : base("Signature algorithm is not supported")
    {
        SignatureAlgorithm = signatureAlgorithm;
    }

    public Oid SignatureAlgorithm { get; }
}
