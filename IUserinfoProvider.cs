using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace ClosureOSS.JwtBearer;

interface IUserinfoProvider
{
    Task<ClaimsIdentity?> GetClaims(TokenValidatedContext context, JwtBearerOptions options);
}
