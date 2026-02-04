using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer.Providers;

internal sealed class DefaultJwtProvider : IJwtProvider
{
    /*
        Appsettings:

        "Authentication": {
            "Provider": "Default",
            "Authority": "https://zitadel.test.slgm.li",
            "Audience": "blog.client",
            "ValidAudiences": [
                "267230930224021668", "267230930224087204@a9blog"
            ]
            ]
        },

        Use on controller:

        [Authorize(Roles = "superuser,admin")]

        or map to policies during startup / main:

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("SuperuserOnly", policy => policy.RequireClaim("superuser"));
        });
    */
    public void Configure(JwtBearerProviderOptions authOptions, JwtBearerOptions options)
    {
        options.IncludeErrorDetails = true;
        // see https://nestenius.se/2022/02/04/asp-net-core-jwtbearer-library-whats-new/
        options.MapInboundClaims = false;
        options.Authority = authOptions.Authority;
        options.Audience = authOptions.Audience;
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateLifetime = true,
            RequireExpirationTime = true,
            // NameClaimType = ClaimTypes.Email,
            NameClaimType = ClaimTypes.NameIdentifier,
            RoleClaimType = ClaimTypes.Role, // claim must be named 'role' and contain a list of strings as role identifiers
            ValidateAudience = true,
            ValidAudiences = [.. authOptions.ValidAudiences ?? []],
            ValidateIssuer = true,
            ValidIssuer = authOptions.ValidIssuer ?? authOptions.Authority,
        };
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = async (context) =>
            {
                //context.HttpContext.
                var logger = IJwtProvider.GetLogger<DefaultJwtProvider>(context.HttpContext.RequestServices);
                logger.LogError("Auth failed {errorMsg}", context.Exception.Message);
                // return Task.CompletedTask;
            },
        };
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
