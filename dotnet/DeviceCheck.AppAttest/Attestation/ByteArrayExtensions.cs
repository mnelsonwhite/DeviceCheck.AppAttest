
using System.Security.Cryptography;

namespace DeviceCheck.AppAttest.Attestation;

internal static class ByteArrayExtensions
{
    public static byte[] SHA256Hash(this byte[] bytes)
    {
        return SHA256.HashData(bytes);
    }
}