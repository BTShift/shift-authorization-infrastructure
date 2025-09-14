using FluentAssertions;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class AuthorizationScopeTests
{
    [Fact]
    public void AuthorizationScope_ShouldHaveCorrectValues()
    {
        // Arrange & Act & Assert
        var scopeType = typeof(AuthorizationScope);

        scopeType.IsEnum.Should().BeTrue();

        var values = Enum.GetValues<AuthorizationScope>();
        values.Should().HaveCount(3);
        values.Should().Contain(AuthorizationScope.Platform);
        values.Should().Contain(AuthorizationScope.Tenant);
        values.Should().Contain(AuthorizationScope.Own);
    }

    [Theory]
    [InlineData(AuthorizationScope.Platform, 0)]
    [InlineData(AuthorizationScope.Tenant, 1)]
    [InlineData(AuthorizationScope.Own, 2)]
    public void AuthorizationScope_ShouldHaveCorrectUnderlyingValues(AuthorizationScope scope, int expectedValue)
    {
        // Arrange & Act
        var actualValue = (int)scope;

        // Assert
        actualValue.Should().Be(expectedValue);
    }

    [Fact]
    public void AuthorizationScope_ShouldConvertToStringCorrectly()
    {
        // Arrange & Act & Assert
        AuthorizationScope.Platform.ToString().Should().Be("Platform");
        AuthorizationScope.Tenant.ToString().Should().Be("Tenant");
        AuthorizationScope.Own.ToString().Should().Be("Own");
    }

    [Fact]
    public void AuthorizationScope_ShouldRepresentHierarchicalAccess()
    {
        // Arrange & Act & Assert
        // Platform scope should have highest privilege level (lowest numeric value)
        ((int)AuthorizationScope.Platform).Should().BeLessThan((int)AuthorizationScope.Tenant);
        ((int)AuthorizationScope.Tenant).Should().BeLessThan((int)AuthorizationScope.Own);
    }
}