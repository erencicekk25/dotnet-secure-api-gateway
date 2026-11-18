using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecureGateway.Gateway.Security;

public sealed record DevTokenResponse(string AccessToken, string TokenType, int ExpiresIn, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Issues short-lived HS256 access tokens for local development and demos only.
/// In a real banking estate this role belongs to a dedicated identity provider
/// (Keycloak, Entra ID, Duende IdentityServer, ...) and the gateway only validates tokens.
/// </summary>
public sealed class DevTokenIssuer(IOptions<JwtOptions> options, TimeProvider timeProvider)
{
    private readonly JsonWebTokenHandler _handler = new();

    public DevTokenResponse Issue(string subject, IEnumerable<string> roles, IEnumerable<string> scopes)
    {
        var jwt = options.Value;
        var now = timeProvider.GetUtcNow();
        var expires = now.AddMinutes(jwt.AccessTokenLifetimeMinutes);

        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, subject));
        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")));
        foreach (var role in roles.Distinct(StringComparer.Ordinal))
        {
            identity.AddClaim(new Claim("role", role));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Subject = identity,
            Claims = new Dictionary<string, object>
            {
                [ScopeRequirement.ClaimType] = string.Join(' ', scopes.Distinct(StringComparer.Ordinal))
            },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                SecurityAlgorithms.HmacSha256)
        };

        return new DevTokenResponse(
            _handler.CreateToken(descriptor),
            "Bearer",
            (int)(expires - now).TotalSeconds,
            expires);
    }
}
