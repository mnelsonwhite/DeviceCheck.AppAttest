namespace DeviceCheck.AppAttest.Attestation;

[CborMap(typeof(string))]
internal class AssertionStatement
{
    [CborProperty("signature")]
    public byte[]? Signature { get; set; }
    [CborProperty("authenticatorData")]
    public byte[]? AuthenticatorData { get; set; }
}
