using System.Collections.Concurrent;

// Sample "Payments" microservice used to demonstrate strict per-user and per-endpoint quotas.
// Payments are accepted asynchronously (202) and stored in memory only.

const string CorrelationHeader = "X-Correlation-ID";
const string UserIdHeader = "X-Gateway-User-Id";

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options =>
{
    options.IncludeScopes = true;
    options.TimestampFormat = "O";
});
builder.Services.AddSingleton<ConcurrentDictionary<Guid, Payment>>();

var app = builder.Build();

app.Use(async (context, next) =>
{
    var correlationId = context.Request.Headers[CorrelationHeader].ToString();
    if (string.IsNullOrEmpty(correlationId))
    {
        correlationId = Guid.NewGuid().ToString("N");
    }

    context.Response.Headers[CorrelationHeader] = correlationId;
    var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Payments");
    using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
    {
        logger.LogInformation("Handling {Method} {Path}", context.Request.Method, context.Request.Path);
        await next(context);
    }
});

app.MapGet("/health", () => Results.Ok(new { status = "Healthy", service = "payments" }));

app.MapPost("/payments", (PaymentRequest request, HttpContext context, ConcurrentDictionary<Guid, Payment> store, ILoggerFactory loggers) =>
{
    var userId = context.Request.Headers[UserIdHeader].ToString();
    if (string.IsNullOrEmpty(userId))
    {
        return Results.Unauthorized();
    }

    var errors = new Dictionary<string, string[]>();
    if (request.Amount is <= 0 or > 1_000_000)
    {
        errors["amount"] = ["Amount must be greater than 0 and at most 1,000,000."];
    }

    if (string.IsNullOrWhiteSpace(request.Currency) || request.Currency.Length != 3)
    {
        errors["currency"] = ["Currency must be a 3-letter ISO 4217 code."];
    }

    if (string.IsNullOrWhiteSpace(request.ToIban) || request.ToIban.Replace(" ", string.Empty).Length is < 15 or > 34)
    {
        errors["toIban"] = ["A valid IBAN is required."];
    }

    if (errors.Count > 0)
    {
        return Results.ValidationProblem(errors);
    }

    var payment = new Payment(
        Guid.NewGuid(),
        userId,
        request.FromAccountId,
        request.ToIban.Replace(" ", string.Empty).ToUpperInvariant(),
        request.Amount,
        request.Currency.ToUpperInvariant(),
        "Accepted",
        DateTimeOffset.UtcNow,
        context.Request.Headers[CorrelationHeader].ToString());

    store[payment.PaymentId] = payment;
    loggers.CreateLogger("Payments").LogInformation(
        "Payment {PaymentId} accepted for user {UserId}: {Amount} {Currency}",
        payment.PaymentId, userId, payment.Amount, payment.Currency);

    return Results.Accepted($"/api/payments/{payment.PaymentId}", payment);
});

app.MapGet("/payments/{paymentId:guid}", (Guid paymentId, HttpContext context, ConcurrentDictionary<Guid, Payment> store) =>
{
    var userId = context.Request.Headers[UserIdHeader].ToString();

    // Object-level authorization: a customer can only read their own payments.
    return store.TryGetValue(paymentId, out var payment) && payment.OwnerUserId == userId
        ? Results.Ok(payment)
        : Results.NotFound();
});

app.Run();

internal sealed record PaymentRequest(string FromAccountId, string ToIban, decimal Amount, string Currency);

internal sealed record Payment(
    Guid PaymentId,
    string OwnerUserId,
    string FromAccountId,
    string ToIban,
    decimal Amount,
    string Currency,
    string Status,
    DateTimeOffset AcceptedAtUtc,
    string CorrelationId);
