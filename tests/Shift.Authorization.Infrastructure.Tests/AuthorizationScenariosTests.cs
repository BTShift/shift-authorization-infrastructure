using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Extensions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

/// <summary>
/// Comprehensive tests for authorization scenarios across the 3-layer scope system
/// </summary>
public class AuthorizationScenariosTests
{
    [Theory]
    [InlineData(UserType.SuperAdmin, "tenant:read", AuthorizationScope.Platform, true)]
    [InlineData(UserType.SuperAdmin, "tenant:read", AuthorizationScope.Tenant, true)]
    [InlineData(UserType.SuperAdmin, "tenant:read", AuthorizationScope.Own, true)]
    [InlineData(UserType.TenantAdmin, "tenant:read", AuthorizationScope.Platform, false)]
    [InlineData(UserType.TenantAdmin, "tenant:read", AuthorizationScope.Tenant, true)]
    [InlineData(UserType.TenantAdmin, "tenant:read", AuthorizationScope.Own, true)]
    [InlineData(UserType.ClientUser, "tenant:read", AuthorizationScope.Platform, false)]
    [InlineData(UserType.ClientUser, "tenant:read", AuthorizationScope.Tenant, false)]
    [InlineData(UserType.ClientUser, "client:read", AuthorizationScope.Own, true)]
    public void HasPermission_WithDifferentUserTypesAndScopes_ReturnsExpectedResult(
        UserType userType, string permission, AuthorizationScope scope, bool expected)
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "test-user",
            tenantId: "test-tenant",
            clientId: "test-client",
            userType: userType,
            permissions: new List<string> { permission });

        // Act
        var result = context.HasPermission(permission, scope);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "any-tenant", true)]
    [InlineData(UserType.TenantAdmin, "same-tenant", true)]
    [InlineData(UserType.TenantAdmin, "different-tenant", false)]
    [InlineData(UserType.ClientUser, "any-tenant", false)]
    public void CanAccessTenant_WithDifferentUserTypes_ReturnsExpectedResult(
        UserType userType, string targetTenant, bool expected)
    {
        // Arrange
        var userTenantId = userType == UserType.TenantAdmin ? "same-tenant" : null;
        var context = new AuthorizationContext(
            userId: "test-user",
            tenantId: userTenantId,
            clientId: "test-client",
            userType: userType,
            permissions: new List<string> { "tenant:read" });

        // Act
        var result = context.CanAccessTenant(targetTenant);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "any-client", true)]
    [InlineData(UserType.TenantAdmin, "client-in-tenant", true)]
    [InlineData(UserType.TenantAdmin, "client-outside-tenant", false)]
    [InlineData(UserType.ClientUser, "same-client", true)]
    [InlineData(UserType.ClientUser, "different-client", false)]
    public void CanAccessClient_WithDifferentUserTypes_ReturnsExpectedResult(
        UserType userType, string targetClient, bool expected)
    {
        // Arrange
        var userClientId = userType == UserType.ClientUser ? "same-client" : null;
        var userTenantId = userType == UserType.TenantAdmin ? "test-tenant" : null;

        var context = new AuthorizationContext(
            userId: "test-user",
            tenantId: userTenantId,
            clientId: userClientId,
            userType: userType,
            permissions: new List<string> { "client:read" });

        // Act
        var result = context.CanAccessClient(targetClient);

        // Assert
        result.Should().Be(expected);
    }

    [Fact]
    public void AuthorizationContext_WithMissingClaims_UsesDefaults()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123")
            // Missing user_type, tenant_id, client_id, and permissions
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().Be("user123");
        context.TenantId.Should().BeNull();
        context.ClientId.Should().BeNull();
        context.UserType.Should().Be(UserType.ClientUser); // Default to most restrictive
        context.Permissions.Should().BeEmpty();
    }

    [Fact]
    public void AuthorizationContext_WithInvalidUserType_DefaultsToClientUser()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("user_type", "invalid_type")
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserType.Should().Be(UserType.ClientUser);
    }

    [Theory]
    [InlineData("superadmin", UserType.SuperAdmin)]
    [InlineData("super_admin", UserType.SuperAdmin)]
    [InlineData("tenantadmin", UserType.TenantAdmin)]
    [InlineData("tenant_admin", UserType.TenantAdmin)]
    [InlineData("clientuser", UserType.ClientUser)]
    [InlineData("client_user", UserType.ClientUser)]
    [InlineData("SUPERADMIN", UserType.SuperAdmin)] // Case insensitive
    [InlineData("", UserType.ClientUser)] // Empty defaults to ClientUser
    public void AuthorizationContext_ParsesUserTypeCorrectly(string userTypeString, UserType expected)
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("user_type", userTypeString)
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserType.Should().Be(expected);
    }

    [Fact]
    public void AuthorizationContext_WithMultiplePermissionClaims_CombinesAllPermissions()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("permission", "read"),
            new("permission", "write"),
            new("permission", "admin"),
            new("scope", "tenant:read client:write"), // Space-separated permissions
            new("permissions", "delete,update") // Comma-separated permissions
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.Permissions.Should().HaveCount(7);
        context.Permissions.Should().Contain("read");
        context.Permissions.Should().Contain("write");
        context.Permissions.Should().Contain("admin");
        context.Permissions.Should().Contain("tenant:read");
        context.Permissions.Should().Contain("client:write");
        context.Permissions.Should().Contain("delete");
        context.Permissions.Should().Contain("update");
    }

    [Fact]
    public void AuthorizationContext_WithDuplicatePermissions_ReturnsDistinctPermissions()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("permission", "read"),
            new("permission", "read"), // Duplicate
            new("scope", "read write"), // Contains duplicate 'read'
        };
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.Permissions.Should().HaveCount(2);
        context.Permissions.Should().Contain("read");
        context.Permissions.Should().Contain("write");
    }

    [Theory]
    [InlineData("platform:admin", AuthorizationScope.Platform)]
    [InlineData("platform:read", AuthorizationScope.Platform)]
    [InlineData("tenant:admin", AuthorizationScope.Tenant)]
    [InlineData("client:read", AuthorizationScope.Own)]
    [InlineData("unknown:permission", AuthorizationScope.Own)] // Default to Own for unknown
    public void GetRequiredScope_WithDifferentPermissions_ReturnsCorrectScope(string permission, AuthorizationScope expected)
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string> { permission });

        // Act
        var result = context.GetRequiredScope(permission);

        // Assert
        result.Should().Be(expected);
    }

    [Fact]
    public void GetRequiredScope_WithNullPermission_ThrowsArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.GetRequiredScope(null!);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void HasPermission_WithNullPermission_ThrowsArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.HasPermission(null!, AuthorizationScope.Own);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CanAccessTenant_WithNullTenantId_ThrowsArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.CanAccessTenant(null!);
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CanAccessClient_WithNullClientId_ThrowsArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext(
            userId: "user123",
            tenantId: "tenant456",
            clientId: "client789",
            userType: UserType.SuperAdmin,
            permissions: new List<string>());

        // Act & Assert
        var action = () => context.CanAccessClient(null!);
        action.Should().Throw<ArgumentException>();
    }
}