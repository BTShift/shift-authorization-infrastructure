using FluentAssertions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class AuthorizationContextTests
{
    [Fact]
    public void Constructor_WithValidClaimsPrincipal_ShouldParseClaimsCorrectly()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, "user123"),
            new("tenant_id", "tenant456"),
            new("client_id", "client789"),
            new("user_type", "tenant_admin"),
            new("permission", "tenant:read"),
            new("permission", "tenant:write"),
            new("scope", "client:read reports:own")
        };

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserId.Should().Be("user123");
        context.TenantId.Should().Be("tenant456");
        context.ClientId.Should().Be("client789");
        context.UserType.Should().Be(UserType.TenantAdmin);
        context.Permissions.Should().HaveCount(4);
        context.Permissions.Should().Contain(new[] { "tenant:read", "tenant:write", "client:read", "reports:own" });
    }

    [Fact]
    public void Constructor_WithTestParameters_ShouldSetPropertiesCorrectly()
    {
        // Arrange
        var permissions = new List<string> { "tenant:read", "client:write" };

        // Act
        var context = new AuthorizationContext("user123", "tenant456", "client789", UserType.TenantAdmin, permissions);

        // Assert
        context.UserId.Should().Be("user123");
        context.TenantId.Should().Be("tenant456");
        context.ClientId.Should().Be("client789");
        context.UserType.Should().Be(UserType.TenantAdmin);
        context.Permissions.Should().BeEquivalentTo(permissions);
    }

    [Fact]
    public void Constructor_WithNullClaimsPrincipal_ShouldThrowArgumentNullException()
    {
        // Arrange & Act & Assert
        var act = () => new AuthorizationContext(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("super_admin", UserType.SuperAdmin)]
    [InlineData("SuperAdmin", UserType.SuperAdmin)]
    [InlineData("tenant_admin", UserType.TenantAdmin)]
    [InlineData("TenantAdmin", UserType.TenantAdmin)]
    [InlineData("client_user", UserType.ClientUser)]
    [InlineData("ClientUser", UserType.ClientUser)]
    [InlineData("unknown", UserType.ClientUser)]
    [InlineData("", UserType.ClientUser)]
    [InlineData(null, UserType.ClientUser)]
    public void Constructor_WithDifferentUserTypes_ShouldParseCorrectly(string userTypeString, UserType expectedUserType)
    {
        // Arrange
        var claims = new List<Claim>();
        if (userTypeString != null)
        {
            claims.Add(new Claim("user_type", userTypeString));
        }

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.UserType.Should().Be(expectedUserType);
    }

    [Fact]
    public void GetRequiredScope_WithKnownPermission_ShouldReturnCorrectScope()
    {
        // Arrange
        var context = new AuthorizationContext("user123", null, null, UserType.SuperAdmin, new List<string>());

        // Act & Assert
        context.GetRequiredScope("platform:admin").Should().Be(AuthorizationScope.Platform);
        context.GetRequiredScope("tenant:read").Should().Be(AuthorizationScope.Tenant);
        context.GetRequiredScope("client:read").Should().Be(AuthorizationScope.Own);
    }

    [Fact]
    public void GetRequiredScope_WithUnknownPermission_ShouldReturnOwnScope()
    {
        // Arrange
        var context = new AuthorizationContext("user123", null, null, UserType.SuperAdmin, new List<string>());

        // Act
        var result = context.GetRequiredScope("unknown:permission");

        // Assert
        result.Should().Be(AuthorizationScope.Own);
    }

    [Fact]
    public void GetRequiredScope_WithNullOrEmptyPermission_ShouldThrowArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext("user123", null, null, UserType.SuperAdmin, new List<string>());

        // Act & Assert
        var actNull = () => context.GetRequiredScope(null!);
        var actEmpty = () => context.GetRequiredScope("");
        var actWhitespace = () => context.GetRequiredScope("   ");

        actNull.Should().Throw<ArgumentException>();
        actEmpty.Should().Throw<ArgumentException>();
        actWhitespace.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "platform:admin", AuthorizationScope.Platform, true)]
    [InlineData(UserType.SuperAdmin, "tenant:read", AuthorizationScope.Tenant, true)]
    [InlineData(UserType.SuperAdmin, "client:read", AuthorizationScope.Own, true)]
    [InlineData(UserType.TenantAdmin, "platform:admin", AuthorizationScope.Platform, false)]
    [InlineData(UserType.TenantAdmin, "tenant:read", AuthorizationScope.Tenant, true)]
    [InlineData(UserType.TenantAdmin, "client:read", AuthorizationScope.Own, true)]
    [InlineData(UserType.ClientUser, "platform:admin", AuthorizationScope.Platform, false)]
    [InlineData(UserType.ClientUser, "tenant:read", AuthorizationScope.Tenant, false)]
    [InlineData(UserType.ClientUser, "client:read", AuthorizationScope.Own, true)]
    public void HasPermission_WithDifferentUserTypesAndScopes_ShouldReturnCorrectResult(
        UserType userType, string permission, AuthorizationScope scope, bool expectedResult)
    {
        // Arrange
        var permissions = new List<string> { "platform:admin", "tenant:read", "client:read" };
        var context = new AuthorizationContext("user123", "tenant456", "client789", userType, permissions);

        // Act
        var result = context.HasPermission(permission, scope);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void HasPermission_WithoutPermission_ShouldReturnFalse()
    {
        // Arrange
        var permissions = new List<string> { "tenant:read" };
        var context = new AuthorizationContext("user123", "tenant456", "client789", UserType.TenantAdmin, permissions);

        // Act
        var result = context.HasPermission("client:write", AuthorizationScope.Own);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "tenant123", true)]
    [InlineData(UserType.SuperAdmin, "tenant456", true)]
    [InlineData(UserType.TenantAdmin, "tenant456", true)]  // Same tenant
    [InlineData(UserType.TenantAdmin, "tenant789", false)] // Different tenant
    [InlineData(UserType.ClientUser, "tenant456", true)]   // Same tenant
    [InlineData(UserType.ClientUser, "tenant789", false)]  // Different tenant
    public void CanAccessTenant_WithDifferentScenarios_ShouldReturnCorrectResult(
        UserType userType, string targetTenantId, bool expectedResult)
    {
        // Arrange
        var context = new AuthorizationContext("user123", "tenant456", "client789", userType, new List<string>());

        // Act
        var result = context.CanAccessTenant(targetTenantId);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "client123", true)]
    [InlineData(UserType.SuperAdmin, "client456", true)]
    [InlineData(UserType.TenantAdmin, "client123", true)]  // TenantAdmin can access clients in their tenant
    [InlineData(UserType.ClientUser, "client789", true)]   // Same client
    [InlineData(UserType.ClientUser, "client456", false)]  // Different client
    public void CanAccessClient_WithDifferentScenarios_ShouldReturnCorrectResult(
        UserType userType, string targetClientId, bool expectedResult)
    {
        // Arrange
        var context = new AuthorizationContext("user123", "tenant456", "client789", userType, new List<string>());

        // Act
        var result = context.CanAccessClient(targetClientId);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Fact]
    public void CanAccessTenant_WithNullOrEmptyTenantId_ShouldThrowArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext("user123", "tenant456", "client789", UserType.TenantAdmin, new List<string>());

        // Act & Assert
        var actNull = () => context.CanAccessTenant(null!);
        var actEmpty = () => context.CanAccessTenant("");
        var actWhitespace = () => context.CanAccessTenant("   ");

        actNull.Should().Throw<ArgumentException>();
        actEmpty.Should().Throw<ArgumentException>();
        actWhitespace.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CanAccessClient_WithNullOrEmptyClientId_ShouldThrowArgumentException()
    {
        // Arrange
        var context = new AuthorizationContext("user123", "tenant456", "client789", UserType.TenantAdmin, new List<string>());

        // Act & Assert
        var actNull = () => context.CanAccessClient(null!);
        var actEmpty = () => context.CanAccessClient("");
        var actWhitespace = () => context.CanAccessClient("   ");

        actNull.Should().Throw<ArgumentException>();
        actEmpty.Should().Throw<ArgumentException>();
        actWhitespace.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Permissions_ShouldReturnCopyOfInternalList()
    {
        // Arrange
        var originalPermissions = new List<string> { "tenant:read", "client:write" };
        var context = new AuthorizationContext("user123", "tenant456", "client789", UserType.TenantAdmin, originalPermissions);

        // Act
        var permissions = context.Permissions;
        permissions.Add("new:permission");

        // Assert
        context.Permissions.Should().HaveCount(2); // Original count unchanged
        context.Permissions.Should().NotContain("new:permission");
    }

    [Fact]
    public void Constructor_WithScopeClaimContainingSpaceSeparatedPermissions_ShouldParseCorrectly()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new("scope", "tenant:read client:write reports:own")
        };

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.Permissions.Should().HaveCount(3);
        context.Permissions.Should().Contain(new[] { "tenant:read", "client:write", "reports:own" });
    }

    [Fact]
    public void Constructor_WithMixedPermissionAndScopeClaims_ShouldCombineAndDeduplicatePermissions()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new("permission", "tenant:read"),
            new("permission", "client:write"),
            new("scope", "tenant:read reports:own") // tenant:read is duplicate
        };

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var context = new AuthorizationContext(claimsPrincipal);

        // Assert
        context.Permissions.Should().HaveCount(3);
        context.Permissions.Should().Contain(new[] { "tenant:read", "client:write", "reports:own" });
    }
}