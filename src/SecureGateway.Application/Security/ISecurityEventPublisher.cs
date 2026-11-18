using SecureGateway.Domain.Security;

namespace SecureGateway.Application.Security;

/// <summary>
/// Fire-and-forget publisher used on the request hot path.
/// Implementations must never block the caller or throw because of storage problems.
/// </summary>
public interface ISecurityEventPublisher
{
    /// <returns><c>false</c> when the event had to be dropped (e.g. back-pressure).</returns>
    bool Publish(SecurityEvent securityEvent);
}
