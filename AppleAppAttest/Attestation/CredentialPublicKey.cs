using Dahomey.Cbor.Attributes;

namespace AppleAppAttest.Attestation;

internal class CredentialPublicKey
{
    [CborProperty("kty")]
    public string? Kty { get; set; }
    [CborProperty("kid")]
    public byte[]? Kid { get; set; }
    [CborProperty("alg")]
    public string? Alg { get; set; }
    [CborProperty("key_ops")]
    public string[]? KeyOps { get; set; }
    [CborProperty("Base IV")]
    public byte[]? BaseIV { get; set; }
}
