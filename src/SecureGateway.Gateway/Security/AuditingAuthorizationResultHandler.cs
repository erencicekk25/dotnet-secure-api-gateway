using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;

namespace SecureGateway.Gateway.Security;

/// <summary>
/// Decorates the default authorization result handling to record every denied access attempt
/// in the security audit trail, then delegates the actual 401/403 response to the default handler.
/// </summary>
public sealed class AuditingAuthorizationResultHandler(ISecurityEventPublisher securityEvents)
    : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _inner = new();

    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Challenged)
        {
            securityEvents.Publish(SecurityEventFactory.Create(
                context,
                SecurityEventType.Unauthorized,
                SecuritySeverity.Medium,
                StatusCodes.Status401Unauthorized,
                "Anonymous or unauthenticated request to a protected resource."));
        }
        else if (authorizeResult.Forbidden)
        {
            var failed = authorizeResult.AuthorizationFailure?.FailedRequirements
                .Select(requirement => requirement.ToString())
                ?? [];

            securityEvents.Publish(SecurityEventFactory.Create(
                context,
                SecurityEventType.Forbidden,
                SecuritySeverity.High,
                StatusCodes.Status403Forbidden,
                "Failed requirements: " + string.Join(" | ", failed)));
        }

        return _inner.HandleAsync(next, context, policy, authorizeResult);
    }
}
