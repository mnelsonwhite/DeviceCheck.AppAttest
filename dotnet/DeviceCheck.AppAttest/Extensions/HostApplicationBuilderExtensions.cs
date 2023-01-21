using DeviceCheck.AppAttest.Attestation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DeviceCheck.AppAttest.Extensions;

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
