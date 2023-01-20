using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dahomey.Cbor;
using DeviceCheck.AppAttest.Attestation;

namespace DeviceCheck.AppAttest.Tests.E2E.Utility;

internal class FakeAttestService
{
    private static readonly X509Certificate2 _rootCertificate;
    private static readonly X509Certificate2 _intermediate;

    static FakeAttestService()
    {
        _rootCertificate = X509Certificate2.CreateFromPem(@"-----BEGIN CERTIFICATE-----
            MIIFxjCCA66gAwIBAgIJAIvQ42LeALnNMA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNV
            BAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJUGFsbyBBbHRvMRAwDgYDVQQK
            DAdDb250b3NvMRQwEgYDVQQDDAtDb250b3NvLmNvbTEgMB4GCSqGSIb3DQEJARYR
            YWRtaW5AY29udG9zby5jb20wHhcNMjIxMjI4MDYzNjU4WhcNMzIxMjI1MDYzNjU4
            WjB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVBhbG8gQWx0
            bzEQMA4GA1UECgwHQ29udG9zbzEUMBIGA1UEAwwLQ29udG9zby5jb20xIDAeBgkq
            hkiG9w0BCQEWEWFkbWluQGNvbnRvc28uY29tMIICIjANBgkqhkiG9w0BAQEFAAOC
            Ag8AMIICCgKCAgEA2A4BZfPxleCzkmsxAHdEGO3r8abSZ3Zhx2yiibfiw2WuMaK2
            finaF7t8hEgZnDTvqBo2aGZ74ldd2fciBu7NzXMaSSmXeYf2VUrBPFNQmH0Guj8T
            2h/hkN/QkN7XDMt+GR6+dVfS0ailO+RyyLe0vTKkmlPEi9RvCaWzNQfPhqW2Qbmh
            r579doAz7KiatDb8TMeXUBOxUBsj6sKrSKc/4gkxIVXCclzREYziggjpmd7303xj
            mInl3BBWpmP9KDBipfPtbLTxPiCdR9z7T1qOVg52GW50qHH9tVIkCkgputgRbd/K
            WlqypbhxAV/NYGxLUVu7JcPCy6RwEQXDD5GvJcw1O6qKSwu98qnB9QHnixiuMzSQ
            3zYAa2OCkkX22lgoARDg40Ih8yevmm7pKO/QO3+i0Wk7JGuIdNnxKu2D495UfmJP
            PVaMc//1aQGv8KjV2JYuDFRm5i697hAVE7gCj3c9T85u2eNNWLgCmB6EzC0wJmOG
            8K1Zj3I0FGlThIzQkWQpYEcLhvr1RheDRqzU2JfCfE/uprWpmoe+gt08Rv1XN3zc
            jiV3EfB3xLhESjKWD4hcTfQFYrZCrJTnEvjSm+ANjx+6v3A5vQenDl0ZY7n7z2z3
            tsWjjKMn4CpXl/AqOpuEJe2ttxxXAIyNMj1tl9FdTeWOPrMaWY00rZ2LBPECAwEA
            AaNTMFEwHQYDVR0OBBYEFMcfaP4prUk6xA3ydRlkgLUYScfRMB8GA1UdIwQYMBaA
            FMcfaP4prUk6xA3ydRlkgLUYScfRMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN
            AQELBQADggIBAD5dWj6xo6nZOI2lxclH+MRXAmGsjhIEkYleAVDgZ7UUCanYgk5I
            rHXfNrHS315rs2g4O32bFFF0zGoqbfS2zlTuBu4mvHcYee7xTkVvZaqpu6IMX/4p
            mG9qnXzJNbdedu8ysXes81TZxnhN4KNYf/Vwpc2/L/+pIW68t7ukifdsD9KxNGuW
            SV0E0LeZQKIXLsKbiiBptDrb9hkpH6UeOqJoeAF/D3EDCE+VecgAv0u4YjCzO1Ki
            KZIx26lMl7ApyHMRq7vL2LQkpmynpoDqIGKuroQqO0DCHOkCWbJrrMBO/4U5ovy+
            6BoObGK96ogjGmMu0EmttCvaQMN1jlHfaJ/F1kY3+1ib9JK0abdJsxrmRDRViCyS
            mSW+tNyZCikSKwUtCkVka2SUJZJxROJXwE26sk4SoDXGXnMkTGWsrXGDcb4Mg6gM
            0L/DGFYYGS511+yn60XdjnWbJlCmtf3v4X4q6b6wkEyOrf+uwKV6QD9NuaGtR4Tv
            xBf71k2EyvHXTp5Y7u7cRk2HtfnulLKRpSWuZX/wH3k0KWqHI6dOjjH5ncAjTV3u
            l9aJBuvKAQh9h+yM8H0bexSCiDyA7rP8lxXAa9Gyuu588Or4lqLcFrau8IErHhrM
            wjyEZDGrfv10Rh8C+4gT2GPpP4IIqx4qo+ijc7rNozmupBApqhxOK8rt
            -----END CERTIFICATE-----",
            @"-----BEGIN RSA PRIVATE KEY-----
            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
            -----END RSA PRIVATE KEY-----"
        );

        _intermediate = X509Certificate2.CreateFromPem(@"-----BEGIN CERTIFICATE-----
            MIIFwTCCA6mgAwIBAgIBATANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJVUzEL
            MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVBhbG8gQWx0bzEQMA4GA1UECgwHQ29udG9z
            bzEUMBIGA1UEAwwLQ29udG9zby5jb20xIDAeBgkqhkiG9w0BCQEWEWFkbWluQGNv
            bnRvc28uY29tMB4XDTIyMTIyODA2NDUyMFoXDTMwMDMzMTA2NDUyMFowaDELMAkG
            A1UEBhMCVVMxCzAJBgNVBAgMAkNBMRAwDgYDVQQKDAdDb250b3NvMRgwFgYDVQQD
            DA9JbnRlcm1lZGlhdGUgQ0ExIDAeBgkqhkiG9w0BCQEWEWFkbWluQGNvbnRvc28u
            Y29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy0qkLLGRI5xqDtIF
            fJ9i77cyDDVnmOAcSE0t/O00xaA5rD0eBI6kJyvm1Xz9t1/vmUPUDwgNM6JwJj/k
            yYWR8u2OYsclzWqi1Lplt2XOOuokIeA0QdDUmjZ5yrSlSENot6/mgAY54MGGIImT
            8eXdblLYRzX47BxjGEjouj5+gmjB1aBy7vm25N+hXEFVS5DVwmJjUKeso6+uxcWq
            D3iAJ3JVXl/eEmmBVk1QrCf1g9xc8e6dvBuma6CJrIi1ULfqdli0yuZ0GT7FvKhS
            1ILXQrD9Y2uo4FHM1KKjI5b+x09WuMtFa+RJ2ZsmqhxKwjNPHzlc0BLljXH8apEQ
            yV8S2Iff/MzHeViHvCY8wKkp0EJnMoV2YpiB3rXtbtpzAn9jCtcF6bD7vcks4u7M
            dSMpIjpYabZZItAYCh6F/Akj8iHbzvtZms80RtMl1GeqQ5CSFL2Vrc7EHNgKSkwe
            a0+NQDUwXPY3IZfiEYeC6cEI6ckWT6XeeSTKH+lk7kNizuFm8oTkTSjrmBsk0v+S
            Fy1bkEUCGWhBoXYuOMb60L1/6AyhGnIpSn0xTj/VWtyxBvB8HYZLcna661oYNNJz
            0C5dnyuQkowE5dCkOqUt3U2ClToljcGgs1Nj8jqHHxg9ZuQyZXiN3FYjqNDHDYfx
            uKoRX/knOYP3c6O0WWrNgbTsPQ8CAwEAAaNmMGQwHQYDVR0OBBYEFBITQbeq5i0q
            c9gqE0mPG39NcGE9MB8GA1UdIwQYMBaAFMcfaP4prUk6xA3ydRlkgLUYScfRMBIG
            A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUA
            A4ICAQBM8DGy5p2xXX6qnPwddqDxoPW1ir6JFkNmFHw+uc7DV8aIvUemAruztOIQ
            iZVWXYMOBcPaUMpO2Rr0Dlt6lTpS1Z2TfgWzoJT+3jQfpK14fnGKLrjdvQiHWt9G
            /tO7/dkK35Warakz+YiaqkQdmhOcydbRt9ZDITJ1fo4MopOYsKofpUb/E41tQuM+
            YXcR/JmDUdy9WIppcyu+Il94zx5YBDr0sNutsC3kcf/e4sAzM3YjCRS8p20LVuFn
            2g/qRhjPB4RlihXwUVT/YjOuT6iKGiXm1lhKR24behgpbzPGQyhBFd8gYLipBaES
            EXXf7aaT4qMIhvdoJHKbl+FhH5c4j/wEpWN0amWozvwvFfS6XVplJZeRD6IEDQaa
            G5xPo2qKLTg3WcnTC5KnufEI5fCXc1vZMt4ovL6VxWiBfl5fgAddGQXwdWnP/j0K
            dSkPQpezX4JjQbJ9XrZf+mbyRCOUOU+4XwDrwUmrjviJ+QMBcngTVGvqFWIIOaTw
            Jb5sIj9lUhvT5N9fR3wP1GrUpcFt6dmyp8ocjDgfsABVEJIpGJ87iLXERCQSBfMZ
            cgVIHPtjATEd5ukSe81wBH8a4r3HrC6kcoNWC7fMEN+Nrc2hVfJuUgO+/POPBB4J
            LKGYc9tHj1yyrtwrkZ01W/oC9Fwaser05ihwQnG92DybbB7u9g==
            -----END CERTIFICATE-----",
            @"-----BEGIN RSA PRIVATE KEY-----
            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
            -----END RSA PRIVATE KEY-----"
        );
    }

    public async Task<(byte[] data, X509Certificate2 cert)> CreateAttestationStatement(
        byte[] challenge,
        string appId,
        RSA key)
    {
        var publicKeyHash = SHA256.HashData(key.ExportRSAPublicKey());

        var authData = new DataBuilder()
            .Add(
                ToRawData(new AuthData
                {
                    rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(appId)),
                    flags = AuthDataFlags.AT,
                    signCount = 0
                })
            )
            .Add(
                ToMemory(new AttestedCredentialData(
                    aaguid: new byte[16],
                    credentialIdLength: Convert.ToUInt16(publicKeyHash.Length),
                    credentialId: publicKeyHash,
                    credentialPublicKey: key.ExportRSAPublicKey()
                ))
            )
            .Build();

        var nonce = await new SHA256HashBuilder()
            .Add(authData.AsSpan())
            .Add(SHA256.HashData(challenge))
            .Build();

        var credCert = GetCredCert(nonce, key);

        var statement = new
        {
            fmt = "apple-appattest",
            attStmt = new
            {
                x5c = new[] {
                    credCert.GetRawCertData(),
                    _intermediate.GetRawCertData()
                },
                receipt = new byte[] { }
            },
            authData = authData
        };

        using var stream = new MemoryStream();
        await Cbor.SerializeAsync(statement, stream);

        return (stream.ToArray(), credCert);
    }

    public X509Certificate2 GetCredCert(ReadOnlySpan<byte> nonce, RSA key)
    {
        var csr = new CertificateRequest(
            "C=US, ST=CA, L=Palo Alto, O=Contoso, CN=Contoso.com/emailAddress=admin@contoso.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushOctetString();
        writer.WriteOctetString(nonce);
        writer.PopOctetString();
        writer.PopSequence();

        var extension = new X509Extension(
            new Oid("1.2.840.113635.100.8.2"),
            writer.Encode(),
            true
        );
        csr.CertificateExtensions.Add(extension);

        return csr.Create(_intermediate, DateTimeOffset.Now, DateTimeOffset.Now.AddMinutes(5), new byte[] { 0x01 });
    }

    public static byte[] ToRawData<T>(T value) where T : struct
    {
        int size = Marshal.SizeOf(value);
        byte[] arr = new byte[size];

        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(value, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        return arr;
    }

    public async Task<byte[]> CreateAssertion(
        RSA key,
        X509Certificate2 credCert,
        HttpContent content,
        string appId,
        uint signCount = 1)
    {
        var clientData = await content.ReadAsByteArrayAsync();
        var clientDataHash = SHA256.HashData(clientData);
        var publicKeyHash = SHA256.HashData(key.ExportRSAPrivateKey());

        var authData = new DataBuilder()
            .Add(
                ToRawData(new AuthData
                {
                    rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(appId)),
                    flags = AuthDataFlags.AT,
                    signCount = signCount
                })
            )
            .Add(
                ToMemory(new AttestedCredentialData(
                    aaguid: new byte[16],
                    credentialIdLength: Convert.ToUInt16(publicKeyHash.Length),
                    credentialId: publicKeyHash,
                    credentialPublicKey: credCert.PublicKey.EncodedKeyValue.RawData
                ))
            )
            .Build();

        var nonce = await new SHA256HashBuilder()
            .Add(authData)
            .Add(clientDataHash)
            .Build();

        using var stream = new MemoryStream();
        await Cbor.SerializeAsync(
            new {
                signature = key.SignData(nonce, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                authenticatorData = authData
            },
            stream
        );

        return stream.ToArray();
    }

    private Memory<byte> ToMemory(AttestedCredentialData attestedCredentialData)
    {
        using var builder = new DataBuilder();

        builder.Add(attestedCredentialData.AAGuid[..16]);

        var span = BitConverter.GetBytes(attestedCredentialData.CredentialIdLength).AsSpan();
        span.Reverse();

        builder.Add(span[..2]);

        builder.Add(attestedCredentialData.CredentialId);
        builder.Add(attestedCredentialData.CredentialPublicKey);

        return builder.Build();
    }

    public const string PublicRootCertificatePem = @"-----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----";
}