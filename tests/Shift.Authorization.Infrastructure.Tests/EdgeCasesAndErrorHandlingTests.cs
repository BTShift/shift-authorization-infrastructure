using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Middleware;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

/// <summary>
/// Tests for edge cases, error handling, and boundary conditions
/// </summary>
public class EdgeCasesAndErrorHandlingTests
{
    [Fact]
    public void AuthorizationContext_WithNullClaimsPrincipal_ThrowsArgumentNullException()
    {
        // Act & Assert
        var action = () => new AuthorizationContext(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AuthorizationContext_WithEmptyClaimsPrincipal_HandlesGracefully()
    {
        // Arrange
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().BeNull();
        context.TenantId.Should().BeNull();
        context.ClientId.Should().BeNull();
        context.UserType.Should().Be(UserType.ClientUser);
        context.Permissions.Should().BeEmpty();
    }

    [Fact]
    public void AuthorizationContext_WithVeryLongClaimValues_HandlesCorrectly()
    {
        // Arrange
        var longUserId = new string('a', 10000); // Very long user ID
        var longTenantId = new string('b', 5000);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, longUserId),
            new("tenant_id", longTenantId),
            new("user_type", "TenantAdmin")
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().Be(longUserId);
        context.TenantId.Should().Be(longTenantId);
        context.UserType.Should().Be(UserType.TenantAdmin);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void AuthorizationContext_WithWhitespaceOnlyClaimValues_TreatsAsNull(string whitespace)
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, whitespace),
            new("tenant_id", whitespace),
            new("client_id", whitespace),
            new("user_type", "TenantAdmin")
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().BeNull();
        context.TenantId.Should().BeNull();
        context.ClientId.Should().BeNull();
    }

    [Fact]
    public void AuthorizationContext_WithSpecialCharactersInClaims_HandlesCorrectly()
    {
        // Arrange
        var specialUserId = "user@domain.com#$%^&*(){}[]|\\:;\"'<>,.?/~`";
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, specialUserId),
            new("user_type", "SuperAdmin"),
            new("permission", "read:all*")
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().Be(specialUserId);
        context.Permissions.Should().Contain("read:all*");
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData(null)]
    public void HasPermission_WithEmptyOrWhitespacePermission_ThrowsArgumentException(string permission)
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: null,
            clientId: null,
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.HasPermission(permission!, AuthorizationScope.Own);
        action.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData(null)]
    public void GetRequiredScope_WithEmptyOrWhitespacePermission_ThrowsArgumentException(string permission)
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: null,
            clientId: null,
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.GetRequiredScope(permission!);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AuthorizationContext_WithHundredsOfPermissions_PerformsWell()
    {
        // Arrange
        var manyPermissions = Enumerable.Range(1, 1000)
            .Select(i => $"permission:{i}")
            .ToList();

        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: manyPermissions);

        // Act & Assert (should complete quickly)
        var start = DateTime.UtcNow;
        for (int i = 1; i <= 100; i++)
        {
            context.HasPermission($"permission:{i}", AuthorizationScope.Platform);
        }
        var duration = DateTime.UtcNow - start;

        duration.Should().BeLessThan(TimeSpan.FromMilliseconds(100));
        context.Permissions.Should().HaveCount(1000);
    }

    [Fact]
    public void ScopeResolver_WithInvalidUserType_HandlesGracefully()
    {
        // Arrange
        var resolver = new ScopeResolver();
        var invalidUserType = (UserType)999; // Invalid enum value

        // Act
        var result = resolver.GetMaximumScope(invalidUserType);

        // Assert - Should default to most restrictive
        result.Should().Be(AuthorizationScope.Own);
    }

    [Fact]
    public void OperationalContextHeaders_Constants_AreCorrect()
    {
        // This ensures the header names don't accidentally change
        OperationalContextHeaders.TenantId.Should().Be("X-Operational-Tenant-Id");
        OperationalContextHeaders.ClientId.Should().Be("X-Operational-Client-Id");
    }

    [Theory]
    [InlineData(UserType.SuperAdmin)]
    [InlineData(UserType.TenantAdmin)]
    [InlineData(UserType.ClientUser)]
    public void UserType_AllValues_AreHandledInSwitchStatements(UserType userType)
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: userType,
            permissions: new List<string> { "test:permission" });

        // Act & Assert - These should not throw exceptions
        var canAccessPlatform = context.HasPermission("test:permission", AuthorizationScope.Platform);
        var canAccessTenant = context.HasPermission("test:permission", AuthorizationScope.Tenant);
        var canAccessOwn = context.HasPermission("test:permission", AuthorizationScope.Own);

        // Results should be consistent with user type capabilities
        switch (userType)
        {
            case UserType.SuperAdmin:
                canAccessPlatform.Should().BeTrue();
                canAccessTenant.Should().BeTrue();
                canAccessOwn.Should().BeTrue();
                break;
            case UserType.TenantAdmin:
                canAccessPlatform.Should().BeFalse();
                canAccessTenant.Should().BeTrue();
                canAccessOwn.Should().BeTrue();
                break;
            case UserType.ClientUser:
                canAccessPlatform.Should().BeFalse();
                canAccessTenant.Should().BeFalse();
                canAccessOwn.Should().BeTrue();
                break;
        }
    }

    [Fact]
    public void AuthorizationContext_WithMixedCasePermissions_IsCaseSensitive()
    {
        // Arrange
        var permissions = new List<string> { "Read", "WRITE", "admin" };
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: null,
            clientId: null,
            userType: UserType.SuperAdmin,
            permissions: permissions);

        // Act & Assert - Permission matching should be case-sensitive
        context.HasPermission("Read", AuthorizationScope.Platform).Should().BeTrue();
        context.HasPermission("read", AuthorizationScope.Platform).Should().BeFalse();
        context.HasPermission("WRITE", AuthorizationScope.Platform).Should().BeTrue();
        context.HasPermission("write", AuthorizationScope.Platform).Should().BeFalse();
    }

    [Theory]
    [InlineData("user@domain.com", "tenant-123", "client_456")]
    [InlineData("123", "456", "789")]
    [InlineData("user with spaces", "tenant with spaces", "client with spaces")]
    public void AuthorizationContext_WithVariousIdFormats_HandlesCorrectly(string userId, string tenantId, string clientId)
    {
        // Arrange & Act
        var context = new AuthorizationContext(
            userId: userId,
            tenantId: tenantId,
            clientId: clientId,
            userType: UserType.TenantAdmin,
            permissions: new List<string> { "test" });

        // Assert
        context.UserId.Should().Be(userId);
        context.TenantId.Should().Be(tenantId);
        context.ClientId.Should().Be(clientId);
    }

    [Fact]
    public async Task AuthorizationContext_ThreadSafety_MultipleThreadsCanReadSafely()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string> { "read", "write", "admin" });

        var tasks = new List<Task>();
        var exceptions = new List<Exception>();

        // Act - Multiple threads accessing the context
        for (int i = 0; i < 10; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (int j = 0; j < 100; j++)
                    {
                        _ = context.UserId;
                        _ = context.TenantId;
                        _ = context.ClientId;
                        _ = context.UserType;
                        _ = context.Permissions.Count;
                        _ = context.HasPermission("read", AuthorizationScope.Platform);
                        _ = context.GetRequiredScope("admin");
                    }
                }
                catch (Exception ex)
                {
                    lock (exceptions)
                    {
                        exceptions.Add(ex);
                    }
                }
            }));
        }

        await Task.WhenAll(tasks.ToArray());

        // Assert
        exceptions.Should().BeEmpty();
    }
}