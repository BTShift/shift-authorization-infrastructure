using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Extensions;
using Shift.Authorization.Infrastructure.Middleware;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests.Middleware;

public class AuthorizationContextMiddlewareIntegrationTests : IAsyncLifetime
{
    private WebApplication? _app;
    private HttpClient? _client;
    private readonly string _jwtSecret = "ThisIsAVerySecretKeyForTestingPurposesOnlyWithAtLeast256Bits!";
    private readonly string _issuer = "test-issuer";
    private readonly string _audience = "test-audience";

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        // Configure services
        builder.Services.AddLogging();
        builder.Services.AddShiftAuthorization(options =>
        {
            options.JwtValidationKey = _jwtSecret;
            options.JwtIssuer = _issuer;
            options.JwtAudience = _audience;
            options.ValidateIssuer = true;
            options.ValidateAudience = true;
            options.ValidateLifetime = true;
            options.EnableOperationalContext = true;
            options.IncludeErrorDetails = true;
        });

        // Add test endpoint
        builder.Services.AddSingleton<TestEndpointService>();

        _app = builder.Build();

        // Configure pipeline
        _app.UseShiftAuthorization();

        // Add test endpoints
        _app.MapGet("/test", (AuthorizationContextService contextService, TestEndpointService service) =>
        {
            var context = contextService.Context;
            if (context == null)
            {
                return Results.Json(new { error = "No authorization context" }, statusCode: 401);
            }

            service.LastContext = context;
            return Results.Json(new
            {
                userId = context.UserId,
                tenantId = context.TenantId,
                clientId = context.ClientId,
                userType = context.UserType.ToString(),
                permissions = context.Permissions
            });
        });

        _app.MapGet("/protected", (IAuthorizationContext context) =>
        {
            if (!context.HasPermission("admin:read", AuthorizationScope.Platform))
            {
                return Results.Json(new { error = "Forbidden" }, statusCode: 403);
            }

            return Results.Json(new { message = "Success" });
        });

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_app != null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    [Fact]
    public async Task Middleware_WithValidJwt_SetsAuthorizationContext()
    {
        // Arrange
        var token = GenerateJwtToken("user123", "tenant456", "client789", UserType.TenantAdmin);
        var request = new HttpRequestMessage(HttpMethod.Get, "/test");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client!.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        // Debug: Log the actual response and token claims
        Console.WriteLine($"Response Status: {response.StatusCode}");
        Console.WriteLine($"Response Content: {content}");
        Console.WriteLine($"JwtRegisteredClaimNames.Sub = '{JwtRegisteredClaimNames.Sub}'");
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadJwtToken(token);
        Console.WriteLine($"Token claims: {string.Join(", ", jsonToken.Claims.Select(c => $"{c.Type}={c.Value}"))}");

        var result = JsonSerializer.Deserialize<JsonDocument>(content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        result?.RootElement.GetProperty("userId").GetString().Should().Be("user123");
        result?.RootElement.GetProperty("tenantId").GetString().Should().Be("tenant456");
        result?.RootElement.GetProperty("clientId").GetString().Should().Be("client789");
        result?.RootElement.GetProperty("userType").GetString().Should().Be("TenantAdmin");
    }

    [Fact]
    public async Task Middleware_WithInvalidJwt_Returns401()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Get, "/test");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "invalid-token");

        // Act
        var response = await _client!.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        content.Should().Contain("unauthorized");
    }

    [Fact]
    public async Task Middleware_WithNoAuthorizationHeader_ProceedsWithoutContext()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Get, "/test");

        // Act
        var response = await _client!.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        content.Should().Contain("No authorization context");
    }

    [Fact]
    public async Task Middleware_WithExpiredToken_Returns401()
    {
        // Arrange
        var token = GenerateJwtToken("user123", "tenant456", "client789", UserType.TenantAdmin, expirationMinutes: -10);
        var request = new HttpRequestMessage(HttpMethod.Get, "/test");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client!.SendAsync(request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Middleware_WithPermissionCheck_ReturnsAppropriateStatus()
    {
        // Arrange - User without required permission
        var token = GenerateJwtToken("user123", "tenant456", "client789", UserType.ClientUser);
        var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client!.SendAsync(request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);

        // Arrange - SuperAdmin with permission
        token = GenerateJwtToken("admin123", null, null, UserType.SuperAdmin, permissions: new[] { "admin:read" });
        request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // Act
        response = await _client!.SendAsync(request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private string GenerateJwtToken(
        string userId,
        string? tenantId,
        string? clientId,
        UserType userType,
        int expirationMinutes = 60,
        string[]? permissions = null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtSecret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_type", userType.ToString())
        };

        if (!string.IsNullOrEmpty(tenantId))
            claims.Add(new Claim("tenant_id", tenantId));

        if (!string.IsNullOrEmpty(clientId))
            claims.Add(new Claim("client_id", clientId));

        // Add permissions
        if (permissions?.Length > 0)
        {
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permission", permission));
            }
        }
        else
        {
            // Default permissions
            claims.Add(new Claim("permission", "tenant:read"));
            claims.Add(new Claim("permission", "client:write"));
        }

        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(expirationMinutes);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            NotBefore = expirationMinutes < 0 ? expires.AddMinutes(-5) : now, // Set NotBefore before Expires for expired tokens
            Expires = expires,
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    // Helper service to capture context
    private sealed class TestEndpointService
    {
        public IAuthorizationContext? LastContext { get; set; }
    }
}