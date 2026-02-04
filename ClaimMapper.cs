using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;

namespace ClosureOSS.JwtBearer;

// based on https://github.com/DuendeSoftware/foss/blob/main/identity-model/src/IdentityModel/Client/JsonElementExtensions.cs#L22
// with several changes
internal static class ClaimMapper
{
    extension(JsonElement element)
    {
        public IEnumerable<Claim> ToClaims(string? issuer)
        {
            var claims = new List<Claim>();
            foreach (var x in element.EnumerateObject())
            {
                var name = string.Equals(x.Name, "groups", System.StringComparison.Ordinal) ? ClaimTypes.Role : x.Name;
                if (x.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in x.Value.EnumerateArray())
                    {
                        claims.Add(new(name, Stringify(item), ClaimValueTypes.String, issuer));
                    }
                }
                else
                {
                    claims.Add(new(name, Stringify(x.Value), ClaimValueTypes.String, issuer));
                }
            }
            return claims;
        }
    }

    // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
    // Boolean needs item.ToString otherwise 'true' => 'True'
    private static string Stringify(JsonElement item) => item.ValueKind == JsonValueKind.String ? item.ToString() : item.GetRawText();
}
