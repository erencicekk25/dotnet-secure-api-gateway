using SecureGateway.Application.RateLimiting;

namespace SecureGateway.UnitTests;

public sealed class RateLimitingOptionsValidatorTests
{
    private readonly RateLimitingOptionsValidator _validator = new();

    [Fact]
    public void Validate_AcceptsConsistentConfiguration()
    {
        var options = new RateLimitingOptions
        {
            DefaultPolicy = "default",
            Policies = [new RateLimitPolicyOptions { Name = "default", PermitLimit = 10, WindowSeconds = 60 }]
        };

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_RejectsMissingDefaultPolicy()
    {
        var options = new RateLimitingOptions
        {
            DefaultPolicy = "missing",
            Policies = [new RateLimitPolicyOptions { Name = "default", PermitLimit = 10, WindowSeconds = 60 }]
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("missing", result.FailureMessage);
    }

    [Theory]
    [InlineData(0, 60)]
    [InlineData(10, 0)]
    [InlineData(-1, 60)]
    public void Validate_RejectsNonPositiveLimits(int permitLimit, int windowSeconds)
    {
        var options = new RateLimitingOptions
        {
            Policies = [new RateLimitPolicyOptions { Name = "default", PermitLimit = permitLimit, WindowSeconds = windowSeconds }]
        };

        Assert.True(_validator.Validate(null, options).Failed);
    }

    [Fact]
    public void Validate_RejectsDuplicatePolicyNamesCaseInsensitively()
    {
        var options = new RateLimitingOptions
        {
            Policies =
            [
                new RateLimitPolicyOptions { Name = "default", PermitLimit = 10, WindowSeconds = 60 },
                new RateLimitPolicyOptions { Name = "DEFAULT", PermitLimit = 20, WindowSeconds = 60 }
            ]
        };

        Assert.True(_validator.Validate(null, options).Failed);
    }
}
