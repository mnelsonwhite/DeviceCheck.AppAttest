using System.Runtime.InteropServices;

namespace DeviceCheck.AppAttest.Attestation;

/// <summary>
/// https://www.w3.org/TR/webauthn/#sctn-authenticator-data
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct AuthData
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] rpIdHash;
    public AuthDataFlags flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] signCountBytes;

    public UInt32 signCount {
        get
        {
            var span = signCountBytes.AsSpan();

            if (BitConverter.IsLittleEndian)
            {
                span.Reverse();
            }
            
            return BitConverter.ToUInt32(span);
        }
        set
        {
            var bytes = BitConverter.GetBytes(value);
            var span = bytes.AsSpan();

            if (BitConverter.IsLittleEndian)
            {
                span.Reverse();
            }

            signCountBytes = span.ToArray();
        }
    }
}
