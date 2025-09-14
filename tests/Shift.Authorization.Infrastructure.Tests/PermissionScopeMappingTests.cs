using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class PermissionScopeMappingTests
{
    [Fact]
    public void PermissionScopeMapping_ShouldInitializeWithDefaults()
    {
        var mapping = new PermissionScopeMapping();

        Assert.Equal(string.Empty, mapping.Permission);
        Assert.Equal(AuthorizationScope.Platform, mapping.RequiredScope); // enum default
        Assert.NotNull(mapping.AllowedUserTypes);
        Assert.Empty(mapping.AllowedUserTypes);
        Assert.Null(mapping.Description);
    }

    [Fact]
    public void PermissionScopeMapping_ShouldSetPropertiesCorrectly()
    {
        var mapping = new PermissionScopeMapping
        {
            Permission = "test:permission",
            RequiredScope = AuthorizationScope.Tenant,
            AllowedUserTypes = ["SuperAdmin", "TenantAdmin"],
            Description = "Test permission description"
        };

        Assert.Equal("test:permission", mapping.Permission);
        Assert.Equal(AuthorizationScope.Tenant, mapping.RequiredScope);
        Assert.Equal(2, mapping.AllowedUserTypes.Count);
        Assert.Contains("SuperAdmin", mapping.AllowedUserTypes);
        Assert.Contains("TenantAdmin", mapping.AllowedUserTypes);
        Assert.Equal("Test permission description", mapping.Description);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, "SuperAdmin", true)]
    [InlineData(UserType.SuperAdmin, "superadmin", true)]
    [InlineData(UserType.SuperAdmin, "super_admin", true)]
    [InlineData(UserType.TenantAdmin, "TenantAdmin", true)]
    [InlineData(UserType.TenantAdmin, "tenantadmin", true)]
    [InlineData(UserType.TenantAdmin, "tenant_admin", true)]
    [InlineData(UserType.ClientUser, "ClientUser", true)]
    [InlineData(UserType.ClientUser, "clientuser", true)]
    [InlineData(UserType.ClientUser, "client_user", true)]
    [InlineData(UserType.SuperAdmin, "TenantAdmin", false)]
    [InlineData(UserType.TenantAdmin, "ClientUser", false)]
    public void IsUserTypeAllowed_ShouldHandleDifferentUserTypeFormats(UserType userType, string allowedUserType, bool expectedResult)
    {
        var mapping = new PermissionScopeMapping
        {
            Permission = "test:permission",
            AllowedUserTypes = [allowedUserType]
        };

        var result = mapping.IsUserTypeAllowed(userType);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void IsUserTypeAllowed_WithEmptyAllowedUserTypes_ShouldReturnFalse()
    {
        var mapping = new PermissionScopeMapping
        {
            Permission = "test:permission",
            AllowedUserTypes = []
        };

        var result = mapping.IsUserTypeAllowed(UserType.SuperAdmin);

        Assert.False(result);
    }

    [Fact]
    public void IsUserTypeAllowed_WithMultipleAllowedUserTypes_ShouldWorkCorrectly()
    {
        var mapping = new PermissionScopeMapping
        {
            Permission = "test:permission",
            AllowedUserTypes = ["SuperAdmin", "TenantAdmin"]
        };

        Assert.True(mapping.IsUserTypeAllowed(UserType.SuperAdmin));
        Assert.True(mapping.IsUserTypeAllowed(UserType.TenantAdmin));
        Assert.False(mapping.IsUserTypeAllowed(UserType.ClientUser));
    }

    [Fact]
    public void IsUserTypeAllowed_ShouldBeCaseInsensitive()
    {
        var mapping = new PermissionScopeMapping
        {
            Permission = "test:permission",
            AllowedUserTypes = ["SUPERADMIN", "tenantadmin", "ClientUser"]
        };

        Assert.True(mapping.IsUserTypeAllowed(UserType.SuperAdmin));
        Assert.True(mapping.IsUserTypeAllowed(UserType.TenantAdmin));
        Assert.True(mapping.IsUserTypeAllowed(UserType.ClientUser));
    }
}