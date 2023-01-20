using System;
using System.Security.Cryptography.X509Certificates;
using DeviceCheck.AppAttest.Extensions;

namespace DeviceCheck.AppAttest.Extensions;

public class X509Certificate2ExtensionsTests
{
    [Fact]
    public void WhenSelfSignedRsa_ShouldBeValid()
    {
        // Arrange
        var pem = @"-----BEGIN CERTIFICATE-----
MIIDYjCCAkoCCQDNAMzg1iuBaTANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJB
VTEMMAoGA1UECAwDUUxEMQwwCgYDVQQHDANzZGYxDzANBgNVBAoMBnNkZnNkZjEP
MA0GA1UECwwGYXNkYXNkMQ8wDQYDVQQDDAZhc2Rhc2QxFTATBgkqhkiG9w0BCQEW
BmFzZGFzZDAeFw0yMjEyMjAwNDE2NThaFw0yMzEyMjAwNDE2NThaMHMxCzAJBgNV
BAYTAkFVMQwwCgYDVQQIDANRTEQxDDAKBgNVBAcMA3NkZjEPMA0GA1UECgwGc2Rm
c2RmMQ8wDQYDVQQLDAZhc2Rhc2QxDzANBgNVBAMMBmFzZGFzZDEVMBMGCSqGSIb3
DQEJARYGYXNkYXNkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxHkL
7eFLuhs9X9ChV0UwvcUvMrJqByIC2b+MeT0GD6asMq+9Amxe16ofR0VST9ISYMRM
mc/PZ7HJsPjsrbHAcbNQLzrPe0L+xCIXsOhC2uSmnlXzRhZow1U4uwU0hdg2mH3H
c2GdoXX5mPEx+wwUpfgZmy0f8cz4IRRRBNpLEO2gr39dBfkI2B61b6ovaHQ/E0eU
2se/QcE6miFO58T/dzxMa4UoPKbJGIuGAOyUqTIGQXtCcG3VGwIgyj88vge4AvPX
fXBNU93vTbe6rWuSG3CWzPa43iaLgxPFhWBNPqlY9mgOgMqA8ygMFasRpu/JjGbl
8Rg9ROyh/J0jQsPZOQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBiAKygLDfWcen6
oRn12iUOsi1dxl+iUeUgEHJybYdxn7818c8bNc43JlkzK3LwUJfTV6aJKO1XadNF
tuOkBDdM1eKbAR4OVodk2ZWpJP7D92zax0edTwRppSp6dDm5uuUInN0qTX2CFS0j
1vQOKyJECKEmPFlQafiu1IE0spU3sUtVkJND2+2usPFTx6GWEH6er01MIhzwMv77
XOoeryJmTxHzdZ3l38Dd1JqXL9Q+yIDrAJLieecNlTeqtHT9kEtyYhG1unVmeHHP
LB59uixTosrGqiXq6PrUYTvCdTRf5ODCasjhwZwrzIHSDfu4Y+XcSZUm9vRx/RUw
Q2/wmE3U
-----END CERTIFICATE-----";

        var cert = X509Certificate2.CreateFromPem(pem);

        // Act
        var result = cert.IsSignedBy(cert);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void WhenSelfSignedEcdsa_ShouldBeValid()
    {
        // Arrange
        var pem = @"-----BEGIN CERTIFICATE-----
MIICOTCCAZsCCQDAh+zFi581eTAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJQTDEQ
MA4GA1UECAwHU2lsZXNpYTERMA8GA1UEBwwIS2F0b3dpY2UxFzAVBgNVBAoMDk15
T3JnYW5pemF0aW9uMRMwEQYDVQQDDApDb21tb25OYW1lMCAXDTIyMTIyMDEwNDUy
MFoYDzQ0ODcwMTMxMTA0NTIwWjBgMQswCQYDVQQGEwJQTDEQMA4GA1UECAwHU2ls
ZXNpYTERMA8GA1UEBwwIS2F0b3dpY2UxFzAVBgNVBAoMDk15T3JnYW5pemF0aW9u
MRMwEQYDVQQDDApDb21tb25OYW1lMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB
Wa+Goyw3cpL59FhcgHnN9Jg3V3PdEuk0NXcmuYwYEyon3tuWiviodjEW4O5x5cnk
D7oLfOdCol/WCMT3nibM/60A5vOsb+m1oPG/Gxx/iNNK+XZSkaRrxJ/em7QfxsvU
XjcLvYExvna8sUOYcI/LMfwou6w9+43Mpxxnbv6bqT7rDsswCgYIKoZIzj0EAwID
gYsAMIGHAkIBFtDGPJ+l0R/BqCHqNmCvdZjA13uYXXCG2NijiZwk4b7EWlhPyIat
oNvmImDG/oqoRnVr2i5jeTPLlV/LfZ0nTxkCQQ1LXYWXxZjVL/ArRqNe4kxljLTv
SLJ8JIgM4Pc1P0x72v1UHTYk0SEWawAcYKPSr7Z+J9rt2WQUalwdVbRYq7Z4
-----END CERTIFICATE-----";

        var cert = X509Certificate2.CreateFromPem(pem);

        // Act
        var result = cert.IsSignedBy(cert);

        // Assert
        Assert.True(result);
    }
}

