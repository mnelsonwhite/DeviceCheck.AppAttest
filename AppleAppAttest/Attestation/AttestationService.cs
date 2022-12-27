
using System.Security.Cryptography;
using AppleAppAttest.Cache;
using Dahomey.Cbor;
using System.Runtime.InteropServices;
using System.Text;
using System.Buffers;
using AppleAppAttest.Extensions;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System;
using System.Diagnostics.CodeAnalysis;

namespace AppleAppAttest.Attestation;


internal class AttestationService : IAttestationService
{
    public byte[] GetChallenge(int length) => RandomNumberGenerator.GetBytes(length);

    public async Task<AttestationResult> ValidateAttestation(
        Stream attestationData,
        X509Certificate2 rootCertificate,
        byte[] challenge,
        string keyId,
        string appId)
    {
        var attestation = await Cbor.DeserializeAsync<AttestationStatement>(attestationData);

        // Step 1
        var (credCert, (intermediate, _)) = attestation.attStmt.GetCertificates();
        if (!intermediate.IsSignedBy(rootCertificate) || !credCert.IsSignedBy(intermediate))
        {
            throw new InvalidAttestation("Certificate Chain");
        }

        // Step 2
        var challengeHash = SHA256.HashData(challenge);
        var clientDataHash = new byte[challengeHash.Length + attestation.authData.Length];
        attestation.authData.CopyTo(clientDataHash, 0);
        challengeHash.CopyTo(clientDataHash, attestation.authData.Length);

        // Step 3
        var nonce = SHA256.HashData(clientDataHash);

        // Step 4
        var credCertOctString = AsnDecoder.ReadOctetString(
            credCert
                .GetExtension(CertificateExtensionOids.CredCert)
                .AsSequence().Span,
            AsnEncodingRules.BER,
            out _
        );

        if (!nonce.SequenceEqual(credCertOctString))
        {
            throw new InvalidAttestation("CredCert Nonce");
        }

        // Step 5
        var publicKeyHash = SHA256.HashData(credCert.PublicKey.EncodedKeyValue.RawData);
        var keyIdData = Convert.FromBase64String(keyId);
        
        if (!publicKeyHash.SequenceEqual(keyIdData))
        {
            throw new InvalidAttestation("CredCert PublicKey");
        }

        // Step 6
        var authData = attestation.authData.ToStruct<AuthData>();
        var appIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(appId));

        if (!authData.rpIdHash.SequenceEqual(appIdHash))
        {
            throw new InvalidAttestation("RPID Hash");
        }

        // Step 7
        if (authData.signCount != 0)
        {
            throw new InvalidAttestation("AuthData Sign Count");
        }

        // Step 8
        if (!authData.flags.HasFlag(AuthDataFlags.AT))
        {
            throw new InvalidAttestation("AuthData Flags");
        }

        var attestedCredentialData = AttestedCredentialData
            .FromMemory(attestation.authData[(Marshal.SizeOf<AuthData>())..].AsMemory());

        // Step 9
        if (!attestedCredentialData.CredentialId.EquivalentTo(keyIdData.AsMemory()))
        {
            throw new InvalidAttestation("AuthData CredentialId");
        }

        return new AttestationResult(
            CredCertData: credCert.RawData,
            Receipt: attestation.attStmt.receipt
        );
    }
}
