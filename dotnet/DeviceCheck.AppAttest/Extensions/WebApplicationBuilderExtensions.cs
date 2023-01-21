using DeviceCheck.AppAttest.Attestation;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace DeviceCheck.AppAttest.Extensions;

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
