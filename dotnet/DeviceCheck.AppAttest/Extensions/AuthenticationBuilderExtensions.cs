using System.Configuration;
using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Cache;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace DeviceCheck.AppAttest.Extensions;

public static class AuthenticationBuilderExtensions
{
    public static AuthenticationBuilder AddAppAttest(
        this AuthenticationBuilder builder,
        IConfiguration configuration,
        string schemeName = AppAttestDefaults.AuthenticationScheme,
        Action<AppAttestAuthOptions>? options = null)
    {
        var section = configuration.GetSection(schemeName);
        var config = section.Get<AppAttestAuthOptions>()
            ?? new AppAttestAuthOptions();
        (options ?? (_ => { }))(config);

        builder.Services
            .Configure<AppAttestAuthOptions>(configuration)
            .PostConfigure(options ?? (_ => { }));

        builder.Services.AddSingleton(typeof(ICacheProvider), config.CacheProviderType);
        builder.Services.AddSingleton<IClock, SystemClock>();
        builder.Services.AddSingleton<IAppAttestService, AppAttestService>();
        
        return builder.AddScheme<AppAttestAuthOptions, AppAttestAuthHandler>(
            schemeName ?? AppAttestDefaults.AuthenticationScheme,
            AppAttestDefaults.DisplayName,
            options ?? (_ => { })
        );
    }
}

public static class WebApplicationBuilderExtensions
{
    public static WebApplicationBuilder AddAppAttest(
        this WebApplicationBuilder builder,
        string schemeName = AppAttestDefaults.AuthenticationScheme,
        Action<AppAttestAuthOptions>? options = null)
    {
        builder.Services.AddAuthentication().AddAppAttest(
            configuration: builder.Configuration,
            options: options
        );

        return builder;
    }
}

public static class HostApplicationBuilderExtensions
{
    public static HostApplicationBuilder AddAppAttest(
        this HostApplicationBuilder builder,
        string schemeName = AppAttestDefaults.AuthenticationScheme,
        Action<AppAttestAuthOptions>? options = null)
    {
        builder.Services.AddAuthentication().AddAppAttest(
            configuration: builder.Configuration,
            options: options
        );

        return builder;
    }
}
