using DeviceCheck.AppAttest.Cbor;

namespace DeviceCheck.AppAttest.Attestation;

[CborMap]
internal partial class AssertionStatement
{
    [CborProperty("signature")]
    public byte[]? Signature { get; set; }
    [CborProperty("authenticatorData")]
    public byte[]? AuthenticatorData { get; set; }
}
