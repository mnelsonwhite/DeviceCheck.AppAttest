using AppleAppAttest.Attestation;
using AppleAppAttest.Cache;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AppleAppAttest;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddAppleAppAttest(
        this AuthenticationBuilder builder,
        Action<AppAttestAuthOptions> options,
        string? schemeName = null)
    {
        builder.Services.AddSingleton<IClock, SystemClock>();
        builder.Services.AddSingleton<IAttestationService, AttestationService>();
        builder.Services.AddSingleton<ICacheProvider, MemoryCacheProvider>();
        builder.Services.AddOptions<AppAttestAuthOptions>(schemeName ?? AppAttestDefaults.AuthenticationScheme);

        return builder.AddScheme<AppAttestAuthOptions, AppAttestAuthHandler>(
            schemeName ?? AppAttestDefaults.AuthenticationScheme,
            AppAttestDefaults.DisplayName,
            options
        );
    }
}