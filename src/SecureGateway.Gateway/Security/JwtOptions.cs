using System.ComponentModel.DataAnnotations;

namespace SecureGateway.Gateway.Security;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>HS256 requires a key of at least 256 bits; 32 ASCII characters is the absolute floor.</summary>
    public const int MinimumSigningKeyLength = 32;

    [Required]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Symmetric signing key. Never commit a real value: supply it via environment variable
    /// (<c>Jwt__SigningKey</c>), user-secrets or a secret manager.
    /// </summary>
    [Required]
    [MinLength(MinimumSigningKeyLength)]
    public string SigningKey { get; set; } = string.Empty;

    [Range(1, 1440)]
    public int AccessTokenLifetimeMinutes { get; set; } = 15;

    [Range(0, 300)]
    public int ClockSkewSeconds { get; set; } = 30;
}

public sealed class DevTokenIssuerOptions
{
    public const string SectionName = "DevTokenIssuer";

    /// <summary>
    /// Enables <c>POST /auth/dev-token</c> for local demos. It is force-disabled in the Production
    /// environment regardless of this flag; real deployments use an external identity provider.
    /// </summary>
    public bool Enabled { get; set; }
}
