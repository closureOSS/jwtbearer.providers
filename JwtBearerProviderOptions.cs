using System.Collections.Generic;

namespace ClosureOSS.JwtBearer;

public record JwtBearerProviderOptions
{
    public AuthProvider Provider { get; set; } = AuthProvider.Default;
    public string Authority { get; set; } = string.Empty;
    public string Audience { get; set; } = "account";
    public List<string> ValidAudiences { get; set; } = [];
    public string? ValidIssuer { get; set; }
    public bool IncludeErrorDetails { get; set; }
    public bool IncludeClaims { get; set; }
}
