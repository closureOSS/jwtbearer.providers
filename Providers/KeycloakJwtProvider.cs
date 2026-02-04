using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer.Providers;

internal sealed class KeycloakJwtProvider : IJwtProvider
{
    /*
        Appsettings:

        "Authentication": {
            "Authority": "https://www.slgm.ch/auth/realms/master",
            "#Authority": "https://keycloak.test.slgm.li/realms/master",
            "Audience": "blog.client",
            "ValidAudiences": [
            "account", "tripbuilder.client", "oauth2-proxy-demo"
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
        // see https://nestenius.se/2022/02/04/asp-net-core-jwtbearer-library-whats-new/
        options.MapInboundClaims = false;
        // options.Authority = "https://keycloak.test.slgm.li/realms/master";
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
            ValidAudiences = [authOptions.Audience, .. authOptions.ValidAudiences ?? []],
            ValidateIssuer = true,
            ValidIssuer = authOptions.ValidIssuer ?? authOptions.Authority,
        };
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = async (context) =>
            {
                var logger = IJwtProvider.GetLogger<KeycloakJwtProvider>(context.HttpContext.RequestServices);
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
                    // var userinfoProvider = context.HttpContext.RequestServices.GetRequiredService<IUserinfoProvider>();
                    // var userinfoIdentity = await userinfoProvider.GetClaims(context, options);
                    // if (userinfoIdentity is not null && userinfoIdentity.Claims.Any())
                    // {
                    //     user.AddIdentity(userinfoIdentity);
                    // }
                    if (authOptions.IncludeClaims)
                    {
                        var logger = IJwtProvider.GetLogger<KeycloakJwtProvider>(context.HttpContext.RequestServices);
                        user.Claims.LogClaims(logger);
                    }
                    var keycloakRealmAccess = user.Claims.FirstOrDefault(x => string.Equals(x.Type, "realm_access", StringComparison.Ordinal));
                    var keycloakResourceAccess = user.Claims.FirstOrDefault(x => string.Equals(x.Type, "resource_access", StringComparison.Ordinal));
                    if (keycloakRealmAccess is not null || keycloakResourceAccess is not null)
                    {
                        var pc = new ClaimsIdentity();
                        if (keycloakRealmAccess is not null)
                        {
                            var realmRoles = JsonSerializer.Deserialize<Dictionary<string, string[]>>(keycloakRealmAccess.Value);
                            if (realmRoles is not null)
                            {
                                if (realmRoles.TryGetValue("roles", out var roles))
                                {
                                    foreach (var role in roles)
                                    {
                                        pc.AddClaim(new Claim(ClaimTypes.Role, $"realm::{role}", valueType: null, keycloakRealmAccess.Issuer));
                                    }
                                }
                            }
                        }
                        if (keycloakResourceAccess is not null)
                        {
                            var resourceClients = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string[]>>>(keycloakResourceAccess.Value);
                            if (resourceClients is not null)
                            {
                                foreach (var (clientName, clients) in resourceClients)
                                {
                                    if (string.Equals(clientName, options.Audience, StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (clients.TryGetValue("roles", out var roles))
                                        {
                                            foreach (var role in roles)
                                            {
                                                pc.AddClaim(new Claim(ClaimTypes.Role, role, valueType: null, keycloakResourceAccess.Issuer));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (pc.Claims.Any())
                        {
                            user.AddIdentity(pc);
                        }
                    }
                }
                // Log.Information("OnTokenValidated");
            },
        };
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
