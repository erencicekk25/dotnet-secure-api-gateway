using Microsoft.Extensions.Options;

namespace SecureGateway.Application.RateLimiting;

/// <summary>
/// Fails application start-up when the rate limiting configuration is inconsistent,
/// instead of discovering a broken quota under production load.
/// </summary>
public sealed class RateLimitingOptionsValidator : IValidateOptions<RateLimitingOptions>
{
    public const int MaxPermitLimit = 1_000_000;
    public const int MaxWindowSeconds = 86_400;

    public ValidateOptionsResult Validate(string? name, RateLimitingOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.KeyPrefix))
        {
            failures.Add("RateLimiting:KeyPrefix must not be empty.");
        }

        if (options.Policies.Count == 0)
        {
            failures.Add("RateLimiting:Policies must contain at least one policy.");
        }

        var duplicates = options.Policies
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key);

        foreach (var duplicate in duplicates)
        {
            failures.Add($"RateLimiting policy '{duplicate}' is defined more than once.");
        }

        foreach (var policy in options.Policies)
        {
            if (string.IsNullOrWhiteSpace(policy.Name))
            {
                failures.Add("Every RateLimiting policy must have a Name.");
                continue;
            }

            if (policy.PermitLimit is < 1 or > MaxPermitLimit)
            {
                failures.Add($"Policy '{policy.Name}': PermitLimit must be between 1 and {MaxPermitLimit}.");
            }

            if (policy.WindowSeconds is < 1 or > MaxWindowSeconds)
            {
                failures.Add($"Policy '{policy.Name}': WindowSeconds must be between 1 and {MaxWindowSeconds}.");
            }

            if (!Enum.IsDefined(policy.PartitionBy))
            {
                failures.Add($"Policy '{policy.Name}': PartitionBy value '{policy.PartitionBy}' is not supported.");
            }
        }

        if (options.FindPolicy(options.DefaultPolicy) is null)
        {
            failures.Add($"RateLimiting:DefaultPolicy '{options.DefaultPolicy}' does not match any configured policy.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
