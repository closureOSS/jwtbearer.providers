using ClosureOSS.JwtBearer.Providers;
using Microsoft.Extensions.DependencyInjection;

namespace ClosureOSS.JwtBearer;


public static class JwtBearerProviderExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>
        /// Enables JwtBearer authentification with some providers
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public IServiceCollection ConfigureJwtBearerProvider()
        {
            services.AddMemoryCache();
            services.AddHttpClient("OIDC").AddAsKeyed();
            services.AddScoped<IUserinfoProvider, UserinfoProvider>();
            services.AddKeyedTransient<IJwtProvider, DefaultJwtProvider>(nameof(AuthProvider.Default));
            services.AddKeyedTransient<IJwtProvider, KeycloakJwtProvider>(nameof(AuthProvider.Keycloak));
            services.AddKeyedTransient<IJwtProvider, PocketIdJwtProvider>(nameof(AuthProvider.PocketId));
            services.AddKeyedTransient<IJwtProvider, ZitadelJwtProvider>(nameof(AuthProvider.Zitadel));
            services.ConfigureOptions<ConfigureJwtBearerOptions>();
            return services;
        }
    }
}
