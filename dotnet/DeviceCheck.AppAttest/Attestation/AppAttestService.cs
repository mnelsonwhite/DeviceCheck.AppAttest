
using System.Security.Cryptography;
using DeviceCheck.AppAttest.Cache;
using System.Runtime.InteropServices;
using System.Text;
using System.Buffers;
using DeviceCheck.AppAttest.Extensions;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System;
using System.Diagnostics.CodeAnalysis;
using DeviceCheck.AppAttest.Cbor;

namespace DeviceCheck.AppAttest.Attestation;

internal class AppAttestService : IAppAttestService
{
    public byte[] GetChallenge(int length) => RandomNumberGenerator.GetBytes(length);

    public Task<AttestationData> ValidateAttestation(
        byte[] attestationData,
        byte[] challenge,
        string keyId,
        string appId,
        X509Certificate2 rootCertificate)
    {
        var attestation = Cbor.Cbor.Deserialize<AttestationObject>(attestationData)
            ?? throw new AttestationException("Unable to deserialize");

        // Step 1
        var (credCert, (intermediate, _)) = attestation.AttestationStatement.GetCertificates();
        if (!intermediate.IsSignedBy(rootCertificate) || !credCert.IsSignedBy(intermediate))
        {
            throw new AttestationException("Certificate Chain");
        }

        // Step 2
        // Step 3
        var nonce = new DataBuilder()
            .Add(attestation.AuthData)
            .Add(SHA256.HashData(challenge))
            .Build()
            .SHA256Hash();

        // Step 4
        var credCertOctString = AsnDecoder.ReadOctetString(
            credCert
                .GetExtension(CertificateExtensionOids.CredCert)
                .AsSequence().Span,
            AsnEncodingRules.DER,
            out _
        );

        if (!nonce.SequenceEqual(credCertOctString))
        {
            throw new AttestationException("CredCert Nonce");
        }

        // Step 5
        var publicKeyHash = SHA256.HashData(credCert.PublicKey.EncodedKeyValue.RawData);
        var keyIdData = Convert.FromBase64String(keyId);
        
        if (!publicKeyHash.SequenceEqual(keyIdData))
        {
            throw new AttestationException("CredCert PublicKey");
        }

        // Step 6
        var authData = attestation.AuthData.ToStruct<AuthData>();
        var appIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(appId));

        if (!authData.rpIdHash.SequenceEqual(appIdHash))
        {
            throw new AttestationException("RPID Hash");
        }

        // Step 7
        if (authData.signCount != 0)
        {
            throw new AttestationException("AuthData Sign Count");
        }

        // Step 8
        if (!authData.flags.HasFlag(AuthDataFlags.AT))
        {
            throw new AttestationException("AuthData Flags");
        }

        // Step 9
        var attestedCredentialData = AttestedCredentialData
            .FromMemory(attestation.AuthData[(Marshal.SizeOf<AuthData>())..].AsMemory());

        if (!attestedCredentialData.CredentialId.EquivalentTo(keyIdData.AsMemory()))
        {
            throw new AttestationException("AuthData CredentialId");
        }

        return Task.FromResult(new AttestationData(
            CredCertData: credCert.RawData,
            Receipt: attestation.AttestationStatement.Receipt,
            Challenge: challenge,
            SignCount: 0
        ));
    }

    public async Task<AttestationData> ValidateAssertion(
        AttestationData attestationData,
        Stream clientDataStream,
        byte[] assertionStatement,
        string appId)
    {
        // Step 1
        var clientDataHash = new Memory<byte>(new byte[32]);
        await SHA256.HashDataAsync(clientDataStream, clientDataHash);

        // Step 2
        var assertion = Cbor.Cbor.Deserialize<AssertionStatement>(assertionStatement)
            ?? throw new AssertionException("Unable to deserialize");

        if (assertion.AuthenticatorData is null)
        {
            throw new AssertionException(nameof(assertion.AuthenticatorData));
        }

        if (assertion.Signature is null)
        {
            throw new AssertionException(nameof(assertion.Signature));
        }

        var nonce = new DataBuilder()
            .Add(assertion.AuthenticatorData)
            .Add(clientDataHash)
            .Build()
            .SHA256Hash();

        // Step 3
        var credCert = attestationData.GetCredCert();
        if (!credCert.PublicKeyVerifiyData(
            nonce,
            assertion.Signature,
            HashAlgorithmName.SHA256
        ))
        {
            throw new AssertionException(nameof(assertion.AuthenticatorData));
        }

        // Step 4
        var authData = assertion.AuthenticatorData.ToStruct<AuthData>();
        var appIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(appId));


        if (!authData.rpIdHash.SequenceEqual(appIdHash))
        {
            throw new AssertionException(nameof(authData.rpIdHash));
        }

        // Step 5
        if (authData.signCount <= attestationData.SignCount)
        {
            throw new AssertionException(nameof(authData.rpIdHash));
        }

        // Step 6
        // WTF how is the challenge embedded into the client data?

        return attestationData with
        {
            SignCount = authData.signCount
        };
    }
}
