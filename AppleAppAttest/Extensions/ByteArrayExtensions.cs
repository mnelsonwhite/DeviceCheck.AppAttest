using System.Runtime.InteropServices;

namespace AppleAppAttest.Extensions;

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
}
