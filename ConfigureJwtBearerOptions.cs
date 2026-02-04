using System;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ClosureOSS.JwtBearer;

internal sealed class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly JwtBearerProviderOptions Config;
    private readonly IServiceProvider ServiceProvider;

    public ConfigureJwtBearerOptions(IOptions<JwtBearerProviderOptions> options, IServiceProvider serviceProvider)
    {
        Config = options.Value;
        ServiceProvider = serviceProvider;
    }

    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        options.Authority = Config.Authority;
        options.Audience = Config.Audience;
        options.IncludeErrorDetails = true;
        options.SaveToken = true;

        var authProvider = ServiceProvider.GetRequiredKeyedService<IJwtProvider>(Config.Provider.ToString());
        authProvider.Configure(Config, options);
    }
}
