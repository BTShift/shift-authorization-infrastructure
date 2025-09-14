using FluentAssertions;
using System.Security.Claims;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class IAuthorizationContextTests
{
    [Fact]
    public void IAuthorizationContextShouldBeInterface()
    {
        // Arrange & Act
        var type = typeof(IAuthorizationContext);

        // Assert
        type.IsInterface.Should().BeTrue();
        type.Name.Should().Be("IAuthorizationContext");
    }

    [Fact]
    public void IAuthorizationContextShouldHaveExpectedProperties()
    {
        // Arrange & Act
        var type = typeof(IAuthorizationContext);
        var properties = type.GetProperties();

        // Assert
        properties.Should().HaveCount(5);
        properties.Should().Contain(p => p.Name == "UserId" && p.PropertyType == typeof(string));
        properties.Should().Contain(p => p.Name == "TenantId" && p.PropertyType == typeof(string));
        properties.Should().Contain(p => p.Name == "ClientId" && p.PropertyType == typeof(string));
        properties.Should().Contain(p => p.Name == "UserType" && p.PropertyType == typeof(UserType));
        properties.Should().Contain(p => p.Name == "Permissions" && p.PropertyType == typeof(List<string>));
    }

    [Fact]
    public void IAuthorizationContextShouldHaveExpectedMethods()
    {
        // Arrange & Act
        var type = typeof(IAuthorizationContext);

        // Assert
        // GetRequiredScope method
        var getRequiredScopeMethod = type.GetMethod("GetRequiredScope");
        getRequiredScopeMethod.Should().NotBeNull();
        getRequiredScopeMethod!.ReturnType.Should().Be(typeof(AuthorizationScope));
        getRequiredScopeMethod.GetParameters().Should().HaveCount(1);
        getRequiredScopeMethod.GetParameters()[0].ParameterType.Should().Be(typeof(string));

        // HasPermission method
        var hasPermissionMethod = type.GetMethod("HasPermission");
        hasPermissionMethod.Should().NotBeNull();
        hasPermissionMethod!.ReturnType.Should().Be(typeof(bool));
        hasPermissionMethod.GetParameters().Should().HaveCount(2);
        hasPermissionMethod.GetParameters()[0].ParameterType.Should().Be(typeof(string));
        hasPermissionMethod.GetParameters()[1].ParameterType.Should().Be(typeof(AuthorizationScope));

        // CanAccessTenant method
        var canAccessTenantMethod = type.GetMethod("CanAccessTenant");
        canAccessTenantMethod.Should().NotBeNull();
        canAccessTenantMethod!.ReturnType.Should().Be(typeof(bool));
        canAccessTenantMethod.GetParameters().Should().HaveCount(1);
        canAccessTenantMethod.GetParameters()[0].ParameterType.Should().Be(typeof(string));

        // CanAccessClient method
        var canAccessClientMethod = type.GetMethod("CanAccessClient");
        canAccessClientMethod.Should().NotBeNull();
        canAccessClientMethod!.ReturnType.Should().Be(typeof(bool));
        canAccessClientMethod.GetParameters().Should().HaveCount(1);
        canAccessClientMethod.GetParameters()[0].ParameterType.Should().Be(typeof(string));
    }
}