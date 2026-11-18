// Sample "Accounts" microservice used to demonstrate gateway routing, identity propagation and
// end-to-end correlation. All data is synthetic and generated in memory.

const string CorrelationHeader = "X-Correlation-ID";
const string UserIdHeader = "X-Gateway-User-Id";

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.TimestampFormat = "O";
});

var app = builder.Build();

// Correlation: reuse the id assigned by the gateway, put it in the logging scope and echo it back.
app.Use(async (context, next) =>
{
    var correlationId = context.Request.Headers[CorrelationHeader].ToString();
    if (string.IsNullOrEmpty(correlationId))
    {
        correlationId = Guid.NewGuid().ToString("N");
    }

    context.Response.Headers[CorrelationHeader] = correlationId;
    var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Accounts");
    using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
    {
        logger.LogInformation("Handling {Method} {Path}", context.Request.Method, context.Request.Path);
        await next(context);
    }
});

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "accounts" }));

app.MapGet("/accounts", (HttpContext context) =>
{
    var userId = context.Request.Headers[UserIdHeader].ToString();
    if (string.IsNullOrEmpty(userId))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(SyntheticAccounts.For(userId));
});

app.MapGet("/accounts/{accountId}/balance", (string accountId, HttpContext context) =>
{
    var userId = context.Request.Headers[UserIdHeader].ToString();
    var account = SyntheticAccounts.For(userId).FirstOrDefault(a => a.AccountId == accountId);

    // Object-level authorization stays in the owning service: the gateway checks roles/scopes,
    // the service checks that this customer actually owns this account (prevents IDOR / BOLA).
    return account is null
        ? Results.NotFound()
        : Results.Ok(new { account.AccountId, account.Currency, account.Balance, asOfUtc = DateTimeOffset.UtcNow });
});

app.MapGet("/public/fx-rates", () => Results.Ok(new
{
    baseCurrency = "TRY",
    asOfUtc = DateTimeOffset.UtcNow,
    rates = new Dictionary<string, decimal> { ["USD"] = 0.0291m, ["EUR"] = 0.0252m, ["GBP"] = 0.0219m }
}));

app.Run();

internal sealed record Account(string AccountId, string Iban, string Currency, decimal Balance);

internal static class SyntheticAccounts
{
    public static IReadOnlyList<Account> For(string userId)
    {
        if (string.IsNullOrEmpty(userId))
        {
            return [];
        }

        // Deterministic per user (FNV-1a; string.GetHashCode is randomized per process) so that
        // repeated calls and restarts return stable demo data.
        var hash = 2166136261u;
        foreach (var c in userId)
        {
            hash = (hash ^ c) * 16777619u;
        }

        var seed = (int)(hash & 0x7FFFFFFF);
        var random = new Random(seed);

        return
        [
            new Account($"ACC-{seed % 100000:D5}-TRY", $"TR00 0000 0000 {seed % 10000:D4} 0000 0001", "TRY", Math.Round((decimal)random.NextDouble() * 250_000m, 2)),
            new Account($"ACC-{seed % 100000:D5}-USD", $"TR00 0000 0000 {seed % 10000:D4} 0000 0002", "USD", Math.Round((decimal)random.NextDouble() * 15_000m, 2))
        ];
    }
}
