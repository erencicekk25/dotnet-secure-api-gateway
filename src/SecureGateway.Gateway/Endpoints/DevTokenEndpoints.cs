using SecureGateway.Gateway.RateLimiting;
using SecureGateway.Gateway.Security;

namespace SecureGateway.Gateway.Endpoints;

public sealed record DevTokenRequest(string? Subject, string[]? Roles, string[]? Scopes);

public static class DevTokenEndpoints
{
    public const string Path = "/auth/dev-token";
    private const int MaxSubjectLength = 64;

    public static IEndpointRouteBuilder MapDevTokenEndpoint(this IEndpointRouteBuilder app)
    {
        app.MapPost(Path, (DevTokenRequest request, DevTokenIssuer issuer) =>
            {
                var errors = Validate(request);
                if (errors.Count > 0)
                {
                    return Results.ValidationProblem(errors);
                }

                return Results.Ok(issuer.Issue(request.Subject!, request.Roles ?? [], request.Scopes ?? []));
            })
            .AllowAnonymous()
            .WithMetadata(new GatewayRateLimitAttribute("auth-ip"))
            .WithName("IssueDevelopmentToken");

        return app;
    }

    internal static Dictionary<string, string[]> Validate(DevTokenRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Subject)
            || request.Subject.Length > MaxSubjectLength
            || !request.Subject.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '@'))
        {
            errors["subject"] = [$"Subject is required, at most {MaxSubjectLength} characters, [A-Za-z0-9-_.@] only."];
        }

        var unknownRoles = (request.Roles ?? []).Where(r => !GatewayRoles.All.Contains(r)).ToArray();
        if (unknownRoles.Length > 0)
        {
            errors["roles"] = [$"Unknown roles: {string.Join(", ", unknownRoles)}. Allowed: {string.Join(", ", GatewayRoles.All)}."];
        }

        var unknownScopes = (request.Scopes ?? []).Where(s => !GatewayScopes.All.Contains(s)).ToArray();
        if (unknownScopes.Length > 0)
        {
            errors["scopes"] = [$"Unknown scopes: {string.Join(", ", unknownScopes)}. Allowed: {string.Join(", ", GatewayScopes.All)}."];
        }

        return errors;
    }
}
