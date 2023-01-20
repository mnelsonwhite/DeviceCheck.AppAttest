using System;
using System.Reflection.PortableExecutable;
using DeviceCheck.AppAttest.Cache;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.VisualStudio.TestPlatform.TestHost;

namespace DeviceCheck.AppAttest.Tests.E2E.Utility;

public class StartupWebApplicationFactory<TStartup> : WebApplicationFactory<StartupWebApplicationFactory<TStartup>> where TStartup : class
{
    protected override IHostBuilder CreateHostBuilder()
    {
        return Host.CreateDefaultBuilder()
            .ConfigureWebHostDefaults(webBuilder =>
            {
                // use whatever config you want here
                webBuilder.UseStartup<TStartup>();
            });
    }
}
