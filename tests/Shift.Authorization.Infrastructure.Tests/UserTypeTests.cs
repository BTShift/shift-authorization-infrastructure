using FluentAssertions;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class UserTypeTests
{
    [Fact]
    public void UserType_ShouldHaveCorrectValues()
    {
        // Arrange & Act & Assert
        var userType = typeof(UserType);

        userType.IsEnum.Should().BeTrue();

        var values = Enum.GetValues<UserType>();
        values.Should().HaveCount(3);
        values.Should().Contain(UserType.SuperAdmin);
        values.Should().Contain(UserType.TenantAdmin);
        values.Should().Contain(UserType.ClientUser);
    }

    [Theory]
    [InlineData(UserType.SuperAdmin, 0)]
    [InlineData(UserType.TenantAdmin, 1)]
    [InlineData(UserType.ClientUser, 2)]
    public void UserType_ShouldHaveCorrectUnderlyingValues(UserType userType, int expectedValue)
    {
        // Arrange & Act
        var actualValue = (int)userType;

        // Assert
        actualValue.Should().Be(expectedValue);
    }

    [Fact]
    public void UserType_ShouldConvertToStringCorrectly()
    {
        // Arrange & Act & Assert
        UserType.SuperAdmin.ToString().Should().Be("SuperAdmin");
        UserType.TenantAdmin.ToString().Should().Be("TenantAdmin");
        UserType.ClientUser.ToString().Should().Be("ClientUser");
    }
}