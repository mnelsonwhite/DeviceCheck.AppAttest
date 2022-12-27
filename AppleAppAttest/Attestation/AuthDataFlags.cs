namespace AppleAppAttest.Attestation;

[Flags]
internal enum AuthDataFlags: byte
{
    UP = 0x01 << 0,
    UV = 0x01 << 2,
    AT = 0x01 << 6,
    ED = 0x01 << 7
}
