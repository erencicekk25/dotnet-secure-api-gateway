using SecureGateway.Domain.Security;
using SecureGateway.Gateway.Extensions;

namespace SecureGateway.Gateway.Security;

internal static class SecurityEventFactory
{
    public static SecurityEvent Create(
        HttpContext context,
        SecurityEventType eventType,
        SecuritySeverity severity,
        int? statusCode,
        string? details) => new()
        {
            EventType = eventType,
            Severity = severity,
            CorrelationId = context.GetCorrelationId(),
            ClientIp = context.GetClientIp(),
            UserId = context.GetUserId(),
            HttpMethod = context.Request.Method,
            Path = context.Request.Path.Value, // query strings are deliberately excluded (may contain PII)
            RouteId = context.GetGatewayRouteId(),
            StatusCode = statusCode,
            Details = details
        };
}
