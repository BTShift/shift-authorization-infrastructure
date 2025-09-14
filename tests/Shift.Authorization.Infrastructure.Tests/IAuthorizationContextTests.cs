using FluentAssertions;
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
        properties.Should().HaveCount(3);
        properties.Should().Contain(p => p.Name == "UserId" && p.PropertyType == typeof(string));
        properties.Should().Contain(p => p.Name == "TenantId" && p.PropertyType == typeof(string));
        properties.Should().Contain(p => p.Name == "Scopes" && p.PropertyType == typeof(IEnumerable<string>));
    }

    [Fact]
    public void IAuthorizationContextShouldHaveHasScopeMethod()
    {
        // Arrange & Act
        var type = typeof(IAuthorizationContext);
        var method = type.GetMethod("HasScope");

        // Assert
        method.Should().NotBeNull();
        method!.ReturnType.Should().Be(typeof(bool));
        method.GetParameters().Should().HaveCount(1);
        method.GetParameters()[0].ParameterType.Should().Be(typeof(string));
        method.GetParameters()[0].Name.Should().Be("scope");
    }
}