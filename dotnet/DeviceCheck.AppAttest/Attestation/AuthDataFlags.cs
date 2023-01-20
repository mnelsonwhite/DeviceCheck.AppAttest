namespace DeviceCheck.AppAttest.Attestation;

[Flags]
internal enum AuthDataFlags: byte
{
    /// <summary>
    /// User Present
    /// </summary>
    UP = 0x01 << 0,
    /// <summary>
    /// User Verified
    /// </summary>
    UV = 0x01 << 2,
    /// <summary>
    /// Attested Credential Data
    /// </summary>
    AT = 0x01 << 6,
    /// <summary>
    /// Extension Data Included
    /// </summary>
    ED = 0x01 << 7
}
