using Microsoft.AspNetCore.Http;
using SecureGateway.Gateway.Extensions;
using SecureGateway.Gateway.Middleware;

namespace SecureGateway.UnitTests;

public sealed class CorrelationIdMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_PreservesValidInboundId()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = "mobile-bff.7f3a_01";
        string? seen = null;

        var middleware = new CorrelationIdMiddleware(ctx =>
        {
            seen = ctx.GetCorrelationId();
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context);

        Assert.Equal("mobile-bff.7f3a_01", seen);
        Assert.Equal("mobile-bff.7f3a_01", context.TraceIdentifier);
    }

    [Theory]
    [InlineData("")]
    [InlineData("contains spaces")]
    [InlineData("crlf\r\ninjected: header")]
    [InlineData("<script>")]
    public async Task InvokeAsync_ReplacesMissingOrUnsafeIds(string inbound)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = inbound;

        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask);
        await middleware.InvokeAsync(context);

        var assigned = context.Request.Headers[CorrelationIdMiddleware.HeaderName].ToString();
        Assert.NotEqual(inbound, assigned);
        Assert.Equal(32, assigned.Length);
        Assert.True(CorrelationIdMiddleware.IsValid(assigned));
    }

    [Fact]
    public void IsValid_RejectsOverlongIds()
    {
        Assert.False(CorrelationIdMiddleware.IsValid(new string('a', CorrelationIdMiddleware.MaxLength + 1)));
        Assert.True(CorrelationIdMiddleware.IsValid(new string('a', CorrelationIdMiddleware.MaxLength)));
    }
}
