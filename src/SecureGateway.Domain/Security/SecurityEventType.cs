namespace SecureGateway.Domain.Security;

public enum SecurityEventType
{
    /// <summary>A caller exceeded one of its sliding-window quotas.</summary>
    RateLimitExceeded = 1,

    /// <summary>A bearer token was presented but failed validation (signature, lifetime, issuer, ...).</summary>
    AuthenticationFailed = 2,

    /// <summary>An anonymous caller attempted to reach a protected resource.</summary>
    Unauthorized = 3,

    /// <summary>An authenticated caller lacked the role or scope required by the route policy.</summary>
    Forbidden = 4,

    /// <summary>The distributed rate limiter backend (Redis) could not be reached.</summary>
    RateLimiterUnavailable = 5
}
