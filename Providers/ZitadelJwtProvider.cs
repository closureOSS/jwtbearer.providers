using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer.Providers;

internal sealed class ZitadelJwtProvider : IJwtProvider
{
    /*
        Appsettings:

        "Authentication": {
            "Provider": "Zitadel",
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
            // RoleClaimType = ClaimTypes.Role, // claim must be named 'role' and contain a list of strings as role identifiers
            RoleClaimType = "groups", // for authentik, keycloak and zitadel handled in event below directly
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
                var logger = IJwtProvider.GetLogger<ZitadelJwtProvider>(context.HttpContext.RequestServices);
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
                    if (authOptions.IncludeClaims)
                    {
                        var logger = IJwtProvider.GetLogger<ZitadelJwtProvider>(context.HttpContext.RequestServices);
                        user.Claims.LogClaims(logger);
                    }
                    var zitaldelRoleClaim = user.Claims.FirstOrDefault(x => string.Equals(x.Type, "urn:zitadel:iam:org:project:roles", System.StringComparison.Ordinal));
                    // var zitaldelRoleClaim = user.Claims.FirstOrDefault(x => x.Type == "urn:zitadel:iam:org:project:266212766686118034:roles");
                    if (zitaldelRoleClaim is not null)
                    {
                        var pc = new ClaimsIdentity();
                        var projectRoles = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(zitaldelRoleClaim.Value);
                        if (projectRoles is not null)
                        {
                            foreach (var (role, _) in projectRoles)
                            {
                                pc.AddClaim(new Claim(ClaimTypes.Role, role, valueType: null, zitaldelRoleClaim.Issuer));
                            }
                        }
                        user.AddIdentity(pc);
                    }
                }
                // Log.Information("OnTokenValidated");
            },
        };
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
