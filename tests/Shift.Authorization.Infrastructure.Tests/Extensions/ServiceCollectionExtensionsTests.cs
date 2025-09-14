using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Extensions;
using Shift.Authorization.Infrastructure.Middleware;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests.Extensions;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddShiftAuthorization_RegistersRequiredServices()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddShiftAuthorization(options =>
        {
            options.EnableOperationalContext = true;
            options.JwtValidationKey = "test-key";
        });

        var provider = services.BuildServiceProvider();

        // Assert
        provider.GetService<AuthorizationContextService>().Should().NotBeNull();
        provider.GetService<IScopeResolver>().Should().NotBeNull();
        provider.GetService<IOperationalContextResolver>().Should().NotBeNull();
        provider.GetService<ScopeBasedAuthorizationService>().Should().NotBeNull();
    }

    [Fact]
    public void AddShiftAuthorization_WithAsyncResolver_RegistersAsyncServices()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddShiftAuthorization(options =>
        {
            options.EnableOperationalContext = true;
            options.EnableAsyncOperationalContextResolution = true;
        });

        var provider = services.BuildServiceProvider();

        // Assert
        provider.GetService<IOperationalContextResolverAsync>().Should().NotBeNull();
    }

    [Fact]
    public void AddShiftAuthorization_DisabledOperationalContext_DoesNotRegisterResolvers()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddShiftAuthorization(options =>
        {
            options.EnableOperationalContext = false;
        });

        var provider = services.BuildServiceProvider();

        // Assert
        provider.GetService<IOperationalContextResolver>().Should().BeNull();
        provider.GetService<IOperationalContextResolverAsync>().Should().BeNull();
    }

    [Fact]
    public void AddPermissionScopeMapping_AddsMapping()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddShiftAuthorization()
            .AddPermissionScopeMapping("custom:permission", AuthorizationScope.Platform, "Custom permission")
            .AddPermissionScopeMapping("another:permission", AuthorizationScope.Tenant);

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>().Value;

        // Assert
        options.PermissionMappings.Should().HaveCount(2);
        options.PermissionMappings[0].Permission.Should().Be("custom:permission");
        options.PermissionMappings[0].RequiredScope.Should().Be(AuthorizationScope.Platform);
        options.PermissionMappings[0].Description.Should().Be("Custom permission");
        options.PermissionMappings[1].Permission.Should().Be("another:permission");
        options.PermissionMappings[1].RequiredScope.Should().Be(AuthorizationScope.Tenant);
    }

    [Fact]
    public void ConfigureJwtValidation_SetsJwtParameters()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddShiftAuthorization()
            .ConfigureJwtValidation(
                validationKey: "super-secret-key",
                issuer: "test-issuer",
                audience: "test-audience");

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>().Value;

        // Assert
        options.JwtValidationKey.Should().Be("super-secret-key");
        options.JwtIssuer.Should().Be("test-issuer");
        options.JwtAudience.Should().Be("test-audience");
        options.ValidateIssuer.Should().BeTrue();
        options.ValidateAudience.Should().BeTrue();
    }

    [Fact]
    public async Task UseShiftAuthorization_AddsMiddlewareToPipeline()
    {
        // Arrange
        var jwtSecret = "ThisIsAVerySecretKeyForTestingPurposesOnlyWithAtLeast256Bits!";
        var builder = WebApplication.CreateBuilder();

        builder.Services.AddShiftAuthorization(options =>
        {
            options.JwtValidationKey = jwtSecret;
            options.JwtIssuer = "test-issuer";
            options.JwtAudience = "test-audience";
            options.EnableOperationalContext = false;
        });

        builder.WebHost.UseTestServer();

        var app = builder.Build();

        app.UseShiftAuthorization();

        app.MapGet("/test", (IServiceProvider serviceProvider) =>
        {
            var contextService = serviceProvider.GetRequiredService<AuthorizationContextService>();
            var context = contextService.Context;

            if (context != null)
            {
                return Results.Ok(new { userId = context.UserId, userType = context.UserType.ToString() });
            }
            return Results.Ok(new { message = "No authorization context" });
        });

        await app.StartAsync();

        // Act
        var client = app.GetTestClient();
        var token = GenerateTestToken(jwtSecret, "test-issuer", "test-audience");

        var request = new HttpRequestMessage(HttpMethod.Get, "/test");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await client.SendAsync(request);

        // Assert
        response.Should().NotBeNull();
        response.IsSuccessStatusCode.Should().BeTrue();

        var content = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response content: {content}");
        content.Should().Contain("\"userId\":\"test-user\"");
        content.Should().Contain("\"userType\":\"TenantAdmin\"");

        await app.StopAsync();
    }

    [Fact]
    public void IAuthorizationContext_ThrowsWhenNotAvailable()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddShiftAuthorization();

        var provider = services.BuildServiceProvider();

        // Act & Assert
        var action = () => provider.GetRequiredService<IAuthorizationContext>();
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*Authorization context is not available*");
    }

    [Fact]
    public void IAuthorizationContext_ReturnsContextWhenSet()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddShiftAuthorization();

        var provider = services.BuildServiceProvider();
        var contextService = provider.GetRequiredService<AuthorizationContextService>();

        var authContext = new AuthorizationContext(
            "user123",
            "tenant456",
            "client789",
            UserType.TenantAdmin,
            new List<string> { "read", "write" });

        // Use reflection to set the context since SetContext is internal
        var setContextMethod = typeof(AuthorizationContextService).GetMethod("SetContext", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        setContextMethod?.Invoke(contextService, new object[] { authContext });

        // Act
        var resolvedContext = provider.GetRequiredService<IAuthorizationContext>();

        // Assert
        resolvedContext.Should().NotBeNull();
        resolvedContext.UserId.Should().Be("user123");
        resolvedContext.TenantId.Should().Be("tenant456");
        resolvedContext.ClientId.Should().Be("client789");
        resolvedContext.UserType.Should().Be(UserType.TenantAdmin);
    }

    private static string GenerateTestToken(string secret, string issuer, string audience)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(secret);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "test-user"),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_type", "TenantAdmin"),
            new("tenant_id", "test-tenant"),
            new("permission", "read"),
            new("permission", "write")
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(60),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}