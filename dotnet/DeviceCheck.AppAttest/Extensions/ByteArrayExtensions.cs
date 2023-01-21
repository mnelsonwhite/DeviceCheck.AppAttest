using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DeviceCheck.AppAttest.Extensions;

internal static class ByteArrayExtensions
{
    public static T ToStruct<T>(this byte[] bytes) where T: struct
    {
        T structVal;
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            structVal = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
        return structVal;
    }

    public static byte[] SHA256Hash(this byte[] bytes)
    {
        return SHA256.HashData(bytes);
    }
}
