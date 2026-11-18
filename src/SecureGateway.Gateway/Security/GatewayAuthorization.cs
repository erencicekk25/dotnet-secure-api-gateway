using Microsoft.AspNetCore.Authorization;

namespace SecureGateway.Gateway.Security;

public static class GatewayRoles
{
    public const string Customer = "Customer";
    public const string Teller = "Teller";
    public const string Auditor = "Auditor";
    public const string Admin = "Admin";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>([Customer, Teller, Auditor, Admin], StringComparer.Ordinal);
}

public static class GatewayScopes
{
    public const string AccountsRead = "accounts:read";
    public const string PaymentsWrite = "payments:write";
    public const string AuditRead = "audit:read";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>([AccountsRead, PaymentsWrite, AuditRead], StringComparer.Ordinal);
}

/// <summary>Names of the authorization policies referenced by YARP routes and local endpoints.</summary>
public static class GatewayPolicies
{
    public const string AccountsRead = "AccountsRead";
    public const string PaymentsWrite = "PaymentsWrite";
    public const string SecurityAuditRead = "SecurityAuditRead";

    public static void Register(AuthorizationOptions options)
    {
        options.AddPolicy(AccountsRead, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(GatewayRoles.Customer, GatewayRoles.Teller, GatewayRoles.Admin)
            .AddRequirements(new ScopeRequirement(GatewayScopes.AccountsRead)));

        options.AddPolicy(PaymentsWrite, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(GatewayRoles.Customer, GatewayRoles.Admin)
            .AddRequirements(new ScopeRequirement(GatewayScopes.PaymentsWrite)));

        options.AddPolicy(SecurityAuditRead, policy => policy
            .RequireAuthenticatedUser()
            .RequireRole(GatewayRoles.Auditor, GatewayRoles.Admin)
            .AddRequirements(new ScopeRequirement(GatewayScopes.AuditRead)));

        // Secure by default: any endpoint (proxied or local) without an explicit policy
        // still requires an authenticated caller. Public routes must opt out explicitly.
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    }
}

/// <summary>
/// Requires an OAuth2-style space-delimited <c>scope</c> claim to contain the given value.
/// Roles answer "who is the caller", scopes answer "what was this token issued for";
/// requiring both limits the blast radius of a leaked token.
/// </summary>
public sealed class ScopeRequirement(string scope)
    : AuthorizationHandler<ScopeRequirement>, IAuthorizationRequirement
{
    public const string ClaimType = "scope";

    public string Scope { get; } = scope;

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        foreach (var claim in context.User.FindAll(ClaimType))
        {
            foreach (var granted in claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(granted, requirement.Scope, StringComparison.Ordinal))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
            }
        }

        return Task.CompletedTask;
    }

    public override string ToString() => $"ScopeRequirement: scope '{Scope}' is required";
}
