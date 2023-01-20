using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DeviceCheck.AppAttest.Extensions;

internal static class X509Certificate2Extensions
{
    public static X509Extension GetExtension(
        this X509Certificate2 certificate,
        string oid
    ) => certificate.Extensions.Single(x => x.Oid?.Value == oid);


    public static string? AsString(
        this X509Extension extension,
        AsnEncodingRules asnEncodingRules = AsnEncodingRules.BER,
        UniversalTagNumber universalTagNumber = UniversalTagNumber.UTF8String
    ) => AsnDecoder.ReadCharacterString(
        extension.RawData,
        asnEncodingRules,
        universalTagNumber,
        out _
    );

    public static Memory<byte> AsSequence(
        this X509Extension extension
    ) => extension.RawData.AsMemory().GetSequence().GetValue();

public static bool IsSignedBy(
    this X509Certificate2 signed,
    X509Certificate2 signedBy)
{
    var signature = signed.Signature();
    var tbs = signed.GetTbsCertificate();
    var alg = signed.SignatureAlgorithm;

    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
    switch (alg)
    {
        case { Value: var value } when value?.StartsWith("1.2.840.113549.1.1.") ?? false:
            return signedBy.GetRSAPublicKey()?.VerifyData(
                tbs,
                signature,
                value switch {
                    "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
                    "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
                    "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
                    _ => throw new UnsupportedAlgorithm(alg)
                },
                RSASignaturePadding.Pkcs1
            ) ?? false;
        case { Value: var value } when value?.StartsWith("1.2.840.10045.") ?? false:
            return signedBy.GetECDsaPublicKey()?.VerifyData(
                tbs,
                signature,
                value switch
                {
                    "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256,
                    "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
                    "1.2.840.10045.4.3.4" => HashAlgorithmName.SHA512,
                    _ => throw new UnsupportedAlgorithm(alg)
                },
                DSASignatureFormat.Rfc3279DerSequence
            ) ?? false;
        default: throw new UnsupportedAlgorithm(alg);
    }
}

    public static bool PublicKeyVerifiyData(
        this X509Certificate2 certificate,
        byte[] data,
        byte[] signature,
        HashAlgorithmName hashAlgorithmName)
    {
        switch (certificate.PublicKey.Oid)
        {
            case { Value: var value } when (value?.Equals("1.2.840.113549.1.1.1") ?? false):
                return certificate.GetRSAPublicKey()?.VerifyData(
                    data,
                    signature,
                    hashAlgorithmName,
                    RSASignaturePadding.Pkcs1
                ) ?? false;
            case { Value: var value } when (value?.Equals("1.2.840.10045.3.1.7") ?? false) || (value?.Equals("1.2.840.10045.2.1") ?? false):
                return certificate.GetECDsaPublicKey()?.VerifyData(
                    data,
                    signature,
                    hashAlgorithmName == HashAlgorithmName.SHA256
                        ? hashAlgorithmName
                        : throw new UnsupportedAlgorithm(certificate.PublicKey.Oid),
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            case { Value: var value } when value?.Equals("1.3.132.0.34") ?? false:
                return certificate.GetECDsaPublicKey()?.VerifyData(
                    data,
                    signature,
                    hashAlgorithmName == HashAlgorithmName.SHA384
                        ? hashAlgorithmName
                        : throw new UnsupportedAlgorithm(certificate.PublicKey.Oid),
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            case { Value: var value } when value?.Equals("1.3.132.0.35") ?? false:
                return certificate.GetECDsaPublicKey()?.VerifyData(
                    data,
                    signature,
                    hashAlgorithmName == HashAlgorithmName.SHA512
                        ? hashAlgorithmName
                        : throw new UnsupportedAlgorithm(certificate.PublicKey.Oid),
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            default: throw new UnsupportedAlgorithm(certificate.PublicKey.Oid);
        }
    }

    public static bool PublicKeyVerifiyHash(
        this X509Certificate2 certificate,
        byte[] hash,
        byte[] signature,
        HashAlgorithmName? hashAlgorithmName = null)
    {
        switch (certificate.PublicKey.Oid)
        {
            case { Value: var value } when (value?.Equals("1.2.840.113549.1.1.1") ?? false):
                return certificate.GetRSAPublicKey()?.VerifyHash(
                    hash,
                    signature,
                    hashAlgorithmName ?? throw new ArgumentException(nameof(hashAlgorithmName)),
                    RSASignaturePadding.Pkcs1
                ) ?? false;
            case { Value: var value } when (value?.Equals("1.2.840.10045.3.1.7") ?? false) || (value?.Equals("1.2.840.10045.2.1") ?? false):
                if (hashAlgorithmName.HasValue && hashAlgorithmName.Value != HashAlgorithmName.SHA256)
                {
                    throw new ArgumentException("Mismatched algorithm", nameof(hashAlgorithmName));
                }
                return certificate.GetECDsaPublicKey()?.VerifyHash(
                    hash,
                    signature,
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            case { Value: var value } when value?.Equals("1.3.132.0.34") ?? false:
                if (hashAlgorithmName.HasValue && hashAlgorithmName.Value != HashAlgorithmName.SHA384)
                {
                    throw new ArgumentException("Mismatched algorithm", nameof(hashAlgorithmName));
                }
                return certificate.GetECDsaPublicKey()?.VerifyHash(
                    hash,
                    signature,
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            case { Value: var value } when value?.Equals("1.3.132.0.35") ?? false:
                if (hashAlgorithmName.HasValue && hashAlgorithmName.Value != HashAlgorithmName.SHA512)
                {
                    throw new ArgumentException("Mismatched algorithm", nameof(hashAlgorithmName));
                }
                return certificate.GetECDsaPublicKey()?.VerifyHash(
                    hash,
                    signature,
                    DSASignatureFormat.Rfc3279DerSequence
                ) ?? false;
            default: throw new UnsupportedAlgorithm(certificate.PublicKey.Oid);
        }
    }

    // https://crypto.stackexchange.com/a/1797
    public static ReadOnlySpan<byte> GetRsSignature(
        ReadOnlySpan<byte> signature,
        AsnEncodingRules encodingRules = AsnEncodingRules.BER)
    {
        AsnDecoder.ReadSequence(
            signature,
            encodingRules,
            out var offset,
            out var length,
            out _
        );

        var sequence = signature.Slice(offset, length);
        var r = AsnDecoder.ReadIntegerBytes(
            sequence,
            encodingRules,
            out var offSet
        );

        var s = AsnDecoder.ReadIntegerBytes(
            sequence[offSet..],
            encodingRules,
            out _
        );

        var result = new byte[r.Length + s.Length];
        r.CopyTo(result);
        s.CopyTo(result.AsSpan().Slice(r.Length));

        return result;
    }

    public static ReadOnlySpan<byte> GetTbsCertificate(
        this X509Certificate2 certificate,
        AsnEncodingRules encodingRules = AsnEncodingRules.BER)
    {
        var signedData = certificate.RawDataMemory;
        AsnDecoder.ReadSequence(
            signedData.Span,
            encodingRules,
            out var offset,
            out var length,
            out _
        );

            //var certificateSpan = signedData.Span[offset..(offset + length)];
            var certificateSpan = signedData.Span.Slice(offset, length);
            AsnDecoder.ReadSequence(
            certificateSpan,
            encodingRules,
            out var tbsOffset,
            out var tbsLength,
            out _
        );

        // include ASN1 4 byte offset to get WHOLE TBS Cert
        return certificateSpan.Slice(tbsOffset - 4, tbsLength + 4);
    }

    /// <summary>
    /// RFC3280 Section 4.1
    /// Depth 1 of the X509 v3 cert is
    /// Certificate  ::=  SEQUENCE  {
    ///     tbsCertificate TBSCertificate,
    ///     signatureAlgorithm   AlgorithmIdentifier,
    ///     signatureValue BIT STRING
    /// }
    ///
    /// https://www.rfc-editor.org/rfc/rfc3280#section-4.1
    /// </summary>
public static byte[] Signature(
    this X509Certificate2 certificate,
    AsnEncodingRules encodingRules = AsnEncodingRules.BER)
{
    var signedData = certificate.RawDataMemory;
    AsnDecoder.ReadSequence(
        signedData.Span,
        encodingRules,
        out var offset,
        out var length,
        out _
    );

    var certificateSpan = signedData.Span.Slice(offset, length);
    AsnDecoder.ReadSequence(
        certificateSpan,
        encodingRules,
        out var tbsOffset,
        out var tbsLength,
        out _
    );

    var offsetSpan = certificateSpan[(tbsOffset + tbsLength)..];
    AsnDecoder.ReadSequence(
        offsetSpan,
        encodingRules,
        out var algOffset,
        out var algLength,
        out _
    );

    return AsnDecoder.ReadBitString(
        offsetSpan[(algOffset + algLength)..],
        encodingRules,
        out _,
        out _
    );
}

    private static Memory<byte> GetSequence(this Memory<byte> span)
    {
        AsnDecoder.ReadSequence(
            span.Span,
            AsnEncodingRules.BER,
            out var offset,
            out var length,
            out _
        );

        return span.Slice(offset, length);
    }

    private static Memory<byte> GetValue(this Memory<byte> span)
    {
        AsnDecoder.ReadEncodedValue(
            span.Span,
            AsnEncodingRules.BER,
            out var offset,
            out var length,
            out _
        );

        return span.Slice(offset, length);
    }
}