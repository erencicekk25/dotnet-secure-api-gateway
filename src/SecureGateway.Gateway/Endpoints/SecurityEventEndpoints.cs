using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;
using SecureGateway.Gateway.RateLimiting;
using SecureGateway.Gateway.Security;

namespace SecureGateway.Gateway.Endpoints;

public static class SecurityEventEndpoints
{
    public const string Path = "/gateway/security-events";

    /// <summary>Read-only view of the audit trail for security operations (SOC) and auditors.</summary>
    public static IEndpointRouteBuilder MapSecurityEventEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(Path, async (
                int? take,
                SecurityEventType? type,
                ISecurityEventStore store,
                CancellationToken cancellationToken) =>
            {
                var events = await store.QueryRecentAsync(take ?? 50, type, cancellationToken);
                return Results.Ok(events);
            })
            .RequireAuthorization(GatewayPolicies.SecurityAuditRead)
            .WithMetadata(new GatewayRateLimitAttribute("audit-per-user"))
            .WithName("GetRecentSecurityEvents");

        return app;
    }
}
