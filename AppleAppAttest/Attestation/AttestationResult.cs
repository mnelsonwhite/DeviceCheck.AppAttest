namespace AppleAppAttest.Attestation;

public record AttestationResult(byte[] CredCertData, byte[] Receipt);
