using System.Configuration;
using DeviceCheck.AppAttest.Attestation;
using DeviceCheck.AppAttest.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DeviceCheck.AppAttest.Tests.E2E.Utility;

public class TestStartup
{
    public const string AppId = "0000000000.com.DeviceCheck.AppAttest.Test";
    public const int ChallengeLength = 64;
    public const string AttestationPath = "/attest";

    public TestStartup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication().AddAppAttest(options => {
            options.RootCertificatePem = FakeAttestService.PublicRootCertificatePem;
            options.ChallengeLength = ChallengeLength;
            options.AppId = AppId;
        });
        services.AddAuthorization();
        services.AddControllers();
        services.AddLogging();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseRouting();
        app.AddAppAttest();
        app.UseAuthorization();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}
