using System.Security.Cryptography;

namespace DeviceCheck.AppAttest.Extensions;

internal class UnsupportedAlgorithm : NotSupportedException
{
    public UnsupportedAlgorithm(string algorithmOid)
        : base("Signature algorithm is not supported")
    {
        Algorithm = new Oid(algorithmOid);
    }

    public UnsupportedAlgorithm(Oid algorithm)
        : base("Signature algorithm is not supported")
    {
        Algorithm = algorithm;
    }

    public Oid Algorithm { get; }
}
