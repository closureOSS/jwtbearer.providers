using System;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer;

interface IJwtProvider
{
    void Configure(JwtBearerProviderOptions providerConfig, JwtBearerOptions options);

    static ILogger GetLogger<T>(IServiceProvider services)
    {
        var logFactory = services.GetRequiredService<ILoggerFactory>();
        return logFactory.CreateLogger<T>();
    }
}
