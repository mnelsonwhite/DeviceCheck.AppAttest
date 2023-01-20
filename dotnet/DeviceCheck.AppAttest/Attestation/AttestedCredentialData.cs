namespace DeviceCheck.AppAttest.Attestation;

internal class AttestedCredentialData
{
    public Memory<byte> AAGuid { get; set; }
    public ushort CredentialIdLength { get; set; }
    public Memory<byte> CredentialId { get; set; }
    public Memory<byte> CredentialPublicKey { get; set; }

    public AttestedCredentialData(
        Memory<byte> aaguid,
        ushort credentialIdLength,
        Memory<byte> credentialId,
        Memory<byte> credentialPublicKey)
    {
        AAGuid = aaguid;
        CredentialIdLength = credentialIdLength;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }

    public static AttestedCredentialData FromMemory(Memory<byte> data)
    {
        var aaguid = data[..16];
        var credentialIdLengthData = data[16..18].Span;

        if (BitConverter.IsLittleEndian)
        {
            credentialIdLengthData.Reverse();
        }
        
        var credentialIdLength = BitConverter.ToUInt16(credentialIdLengthData);
        var credentialId = data.Slice(18, credentialIdLength);
        var credentialPublicKey = data[(18 + credentialIdLength)..];

        return new AttestedCredentialData(
            aaguid: aaguid,
            credentialIdLength: credentialIdLength,
            credentialId: credentialId,
            credentialPublicKey: credentialPublicKey
        );
    }
}
