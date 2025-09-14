using Xunit;
using System.Reflection;

namespace Shift.Authorization.Infrastructure.Tests;

public class IScopeResolverTests
{
    [Fact]
    public void IScopeResolverShouldBeInterface()
    {
        var type = typeof(IScopeResolver);
        Assert.True(type.IsInterface);
    }

    [Fact]
    public void IScopeResolverShouldHaveExpectedMethods()
    {
        var type = typeof(IScopeResolver);
        var methods = type.GetMethods();

        // Check for GetRequiredScope method
        var getRequiredScopeMethod = methods.FirstOrDefault(m =>
            m.Name == "GetRequiredScope" &&
            m.GetParameters().Length == 1 &&
            m.GetParameters()[0].ParameterType == typeof(string) &&
            m.ReturnType == typeof(AuthorizationScope));
        Assert.NotNull(getRequiredScopeMethod);

        // Check for GetPermissionsForScope method
        var getPermissionsForScopeMethod = methods.FirstOrDefault(m =>
            m.Name == "GetPermissionsForScope" &&
            m.GetParameters().Length == 1 &&
            m.GetParameters()[0].ParameterType == typeof(AuthorizationScope) &&
            m.ReturnType == typeof(IReadOnlyList<string>));
        Assert.NotNull(getPermissionsForScopeMethod);

        // Check for CanOperateAtScope method
        var canOperateAtScopeMethod = methods.FirstOrDefault(m =>
            m.Name == "CanOperateAtScope" &&
            m.GetParameters().Length == 2 &&
            m.GetParameters()[0].ParameterType == typeof(UserType) &&
            m.GetParameters()[1].ParameterType == typeof(AuthorizationScope) &&
            m.ReturnType == typeof(bool));
        Assert.NotNull(canOperateAtScopeMethod);

        // Check for GetMaximumScope method
        var getMaximumScopeMethod = methods.FirstOrDefault(m =>
            m.Name == "GetMaximumScope" &&
            m.GetParameters().Length == 1 &&
            m.GetParameters()[0].ParameterType == typeof(UserType) &&
            m.ReturnType == typeof(AuthorizationScope));
        Assert.NotNull(getMaximumScopeMethod);
    }

    [Fact]
    public void IScopeResolverShouldBeInCorrectNamespace()
    {
        var type = typeof(IScopeResolver);
        Assert.Equal("Shift.Authorization.Infrastructure", type.Namespace);
    }
}