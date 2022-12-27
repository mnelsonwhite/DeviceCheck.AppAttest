using System.Runtime.InteropServices;

namespace AppleAppAttest.Attestation;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct AuthData
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] rpIdHash;
    public AuthDataFlags flags;
    [MarshalAs(UnmanagedType.U4, SizeConst = 4)]
    public UInt32 signCount;
}
