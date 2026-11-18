using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureGateway.Application.RateLimiting;
using SecureGateway.Application.Security;
using SecureGateway.Domain.Security;
using SecureGateway.Gateway.RateLimiting;

namespace SecureGateway.UnitTests;

public sealed class GatewayRateLimitingMiddlewareTests
{
    private static readonly RateLimitPolicyOptions DefaultPolicy =
        new() { Name = "default", PartitionBy = PartitionStrategy.ClientIp, PermitLimit = 5, WindowSeconds = 60 };

    [Fact]
    public async Task Allowed_CallsNextAndWritesQuotaHeaders()
    {
        var limiter = new FakeRateLimiter(_ => new RateLimitDecision(true, DefaultPolicy, 4, TimeSpan.Zero));
        var (middleware, events, nextCalled) = Create(limiter);
        var context = CreateContext();

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled());
        Assert.Equal("5", context.Response.Headers[GatewayRateLimitingMiddleware.LimitHeader]);
        Assert.Equal("4", context.Response.Headers[GatewayRateLimitingMiddleware.RemainingHeader]);
        Assert.Empty(events.Events);
    }

    [Fact]
    public async Task Rejected_Returns429WithRetryAfterAndPublishesSecurityEvent()
    {
        var limiter = new FakeRateLimiter(_ => new RateLimitDecision(false, DefaultPolicy, 0, TimeSpan.FromMilliseconds(2_400)));
        var (middleware, events, nextCalled) = Create(limiter);
        var context = CreateContext();

        await middleware.InvokeAsync(context);

        Assert.False(nextCalled());
        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("3", context.Response.Headers.RetryAfter);
        var securityEvent = Assert.Single(events.Events);
        Assert.Equal(SecurityEventType.RateLimitExceeded, securityEvent.EventType);
        Assert.Equal("203.0.113.7", securityEvent.ClientIp);
    }

    [Theory]
    [InlineData(true, StatusCodes.Status200OK)]
    [InlineData(false, StatusCodes.Status503ServiceUnavailable)]
    public async Task LimiterOutage_HonoursFailOpenSetting(bool failOpen, int expectedStatus)
    {
        var limiter = new FakeRateLimiter(_ =>
            throw new RateLimiterUnavailableException("down", new TimeoutException()));
        var (middleware, events, nextCalled) = Create(limiter, failOpen);
        var context = CreateContext();

        await middleware.InvokeAsync(context);

        Assert.Equal(failOpen, nextCalled());
        Assert.Equal(expectedStatus, context.Response.StatusCode);
        Assert.Equal(SecurityEventType.RateLimiterUnavailable, Assert.Single(events.Events).EventType);
    }

    [Fact]
    public void ResolvePartition_UsesSubjectForAuthenticatedUsersAndIpOtherwise()
    {
        var anonymous = CreateContext();
        Assert.Equal("anonymous-203.0.113.7", GatewayRateLimitingMiddleware.ResolvePartition(anonymous, PartitionStrategy.User));

        var authenticated = CreateContext();
        authenticated.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "customer-42")], "Bearer"));
        Assert.Equal("customer-42", GatewayRateLimitingMiddleware.ResolvePartition(authenticated, PartitionStrategy.User));
        Assert.Equal("all", GatewayRateLimitingMiddleware.ResolvePartition(authenticated, PartitionStrategy.Endpoint));
    }

    private static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/api/accounts";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static (GatewayRateLimitingMiddleware Middleware, RecordingPublisher Events, Func<bool> NextCalled) Create(
        IRateLimiter limiter,
        bool failOpen = true)
    {
        var options = new RateLimitingOptions { FailOpen = failOpen, Policies = [DefaultPolicy] };
        var events = new RecordingPublisher();
        var called = false;

        var middleware = new GatewayRateLimitingMiddleware(
            _ =>
            {
                called = true;
                return Task.CompletedTask;
            },
            limiter,
            new RateLimitPolicyResolver(NullLogger<RateLimitPolicyResolver>.Instance),
            events,
            new StaticOptionsMonitor<RateLimitingOptions>(options),
            NullLogger<GatewayRateLimitingMiddleware>.Instance);

        return (middleware, events, () => called);
    }

    private sealed class FakeRateLimiter(Func<IReadOnlyList<RateLimitRule>, RateLimitDecision> decide) : IRateLimiter
    {
        public ValueTask<RateLimitDecision> TryAcquireAsync(IReadOnlyList<RateLimitRule> rules, CancellationToken cancellationToken) =>
            ValueTask.FromResult(decide(rules));
    }

    private sealed class RecordingPublisher : ISecurityEventPublisher
    {
        public List<SecurityEvent> Events { get; } = [];

        public bool Publish(SecurityEvent securityEvent)
        {
            Events.Add(securityEvent);
            return true;
        }
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;

        public T Get(string? name) => value;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
