using SecureGateway.Gateway.Endpoints;

namespace SecureGateway.UnitTests;

public sealed class DevTokenValidationTests
{
    [Fact]
    public void Validate_AcceptsKnownRolesAndScopes()
    {
        var request = new DevTokenRequest("customer-42", ["Customer"], ["accounts:read", "payments:write"]);

        Assert.Empty(DevTokenEndpoints.Validate(request));
    }

    [Fact]
    public void Validate_RejectsPrivilegeNamesThatAreNotDefined()
    {
        var request = new DevTokenRequest("customer-42", ["SuperAdmin"], ["*"]);

        var errors = DevTokenEndpoints.Validate(request);

        Assert.Contains("roles", errors.Keys);
        Assert.Contains("scopes", errors.Keys);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("user name")]
    [InlineData("user\nname")]
    public void Validate_RejectsInvalidSubjects(string? subject)
    {
        Assert.Contains("subject", DevTokenEndpoints.Validate(new DevTokenRequest(subject, null, null)).Keys);
    }
}
