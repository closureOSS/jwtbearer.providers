using System.Linq;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer.Providers;

internal sealed class PocketIdJwtProvider : IJwtProvider
{
    /*
        Appsettings:

        "Authentication": {
            "Provider": "PocketId",
            "Authority": "https://login.schufelberg.ch",
            "Audience": "blog.client",
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
            NameClaimType = "sub", //ClaimTypes.Name,
                                   //RoleClaimType = "groups",
            ValidateAudience = true,
            ValidAudiences = [authOptions.Audience, .. authOptions.ValidAudiences ?? []],
            ValidateIssuer = true,
            ValidIssuer = authOptions.ValidIssuer ?? authOptions.Authority,
        };
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = async (context) =>
            {
                var logger = IJwtProvider.GetLogger<PocketIdJwtProvider>(context.HttpContext.RequestServices);
                logger.LogError("Auth failed {errorMsg}", context.Exception.Message);
            },
            // OnMessageReceived = async (context) =>
            // {
            //     Log.Information("Message received");
            // },
            OnTokenValidated = async (context) =>
            {
                var user = context.Principal;
                if (user is not null)
                {
                    var userinfoProvider = context.HttpContext.RequestServices.GetRequiredService<IUserinfoProvider>();
                    var userinfoIdentity = await userinfoProvider.GetClaims(context, options);
                    if (userinfoIdentity is not null && userinfoIdentity.Claims.Any())
                    {
                        user.AddIdentity(userinfoIdentity);
                    }
                    if (authOptions.IncludeClaims)
                    {
                        var logger = IJwtProvider.GetLogger<PocketIdJwtProvider>(context.HttpContext.RequestServices);
                        user.Claims.LogClaims(logger);
                    }
                }
                // Log.Information("OnTokenValidated");
            },
        };
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
