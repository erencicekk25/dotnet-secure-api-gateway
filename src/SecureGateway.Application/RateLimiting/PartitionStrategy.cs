namespace SecureGateway.Application.RateLimiting;

/// <summary>Defines which dimension of a request a quota is counted against.</summary>
public enum PartitionStrategy
{
    /// <summary>One counter per client IP address. Effective against anonymous floods and credential stuffing.</summary>
    ClientIp = 0,

    /// <summary>One counter per authenticated subject (<c>sub</c> claim). Falls back to the client IP for anonymous calls.</summary>
    User = 1,

    /// <summary>One shared counter for the whole route. Protects fragile downstream systems (e.g. core banking) from aggregate overload.</summary>
    Endpoint = 2
}
