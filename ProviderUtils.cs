using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;

namespace ClosureOSS.JwtBearer;

internal static class ProviderUtils
{
    public static void LogClaims(this IEnumerable<Claim> claims, ILogger logger)
    {
        var op = new StringBuilder();
        foreach (var claim in claims ?? [])
        {
            op.AppendLine($"{claim.Type}: {claim.Value}  [{claim.Issuer}, {claim.ValueType}]");
        }
        logger.LogInformation("Claims are: {claims}", op.ToString());
    }
}
