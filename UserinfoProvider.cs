using System;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer;

internal sealed class UserinfoProvider : IUserinfoProvider
{
    private readonly IMemoryCache Cache;
    private readonly ILogger<IUserinfoProvider> Log;


    public UserinfoProvider(IMemoryCache memoryCache, ILogger<IUserinfoProvider> logger)
    {
        Cache = memoryCache;
        Log = logger;
    }

    public async Task<ClaimsIdentity?> GetClaims(TokenValidatedContext context, JwtBearerOptions options)
    {
        var user = context.Principal;
        if (user is null || options.ConfigurationManager is null)
        {
            return default;
        }
        var subject = context.Principal?.Identity?.Name ?? "anonymous";
        if (Cache.TryGetValue(subject, out ClaimsIdentity? cachedIdentity))
        {
            if (cachedIdentity is not null)
            {
                return cachedIdentity;
            }
        }
        var oidcConfig = await options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);
        if (oidcConfig is null)
        {
            return default;
        }
        try
        {
            var httpClient = context.HttpContext.RequestServices.GetRequiredKeyedService<HttpClient>("OIDC");
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.SecurityToken.UnsafeToString());
            var response = await httpClient.GetStringAsync(oidcConfig.UserInfoEndpoint, context.HttpContext.RequestAborted);
            var userinfoResponse = JsonDocument.Parse(response);
            var claims = userinfoResponse.RootElement.ToClaims(oidcConfig.Issuer);
            // Log.Information("Userinfo is {response} {userinfo}", response, userinfoResponse);
            var identity = new ClaimsIdentity(claims);
            Cache.Set(subject, identity, new DateTimeOffset(context.SecurityToken.ValidTo));
            return identity;
        }
        catch (Exception e)
        {
            Log.LogError(e, "Retrieving userinfo from OIDC provider {issuer} for {sub} failed ", oidcConfig.Issuer, user.Identity?.Name);
            return default;
        }
    }
}
