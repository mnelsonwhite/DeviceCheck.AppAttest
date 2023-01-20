using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Cache;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace DeviceCheck.AppAttest.Extensions;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddAppAttest(
        this AuthenticationBuilder builder,
        Action<AppAttestAuthOptions>? options = null,
        string? schemeName = null)
    {
        builder.Services.AddSingleton<IClock, SystemClock>();
        builder.Services.AddSingleton<IAppAttestService, AppAttestService>();
        builder.Services.AddSingleton<ICacheProvider, MemoryCacheProvider>();
        builder.Services
            .AddOptions<AppAttestAuthOptions>()
            .BindConfiguration(schemeName ?? AppAttestDefaults.AuthenticationScheme)
            .PostConfigure(options ?? (_ => { }));

        return builder.AddScheme<AppAttestAuthOptions, AppAttestAuthHandler>(
            schemeName ?? AppAttestDefaults.AuthenticationScheme,
            AppAttestDefaults.DisplayName,
            options ?? (_ => { })
        );
    }
}
