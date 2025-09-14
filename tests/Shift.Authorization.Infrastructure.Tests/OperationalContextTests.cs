using FluentAssertions;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class OperationalContextTests
{
    [Fact]
    public void GetEffectiveTenantId_ShouldReturnOperationTenantId_WhenSet()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationTenantId = "operation-tenant-123",
            IsOperationalContext = true
        };

        // Act
        var effectiveTenantId = context.GetEffectiveTenantId("original-tenant-456");

        // Assert
        effectiveTenantId.Should().Be("operation-tenant-123");
    }

    [Fact]
    public void GetEffectiveTenantId_ShouldReturnOriginalTenantId_WhenOperationTenantIdIsNull()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationTenantId = null,
            IsOperationalContext = false
        };

        // Act
        var effectiveTenantId = context.GetEffectiveTenantId("original-tenant-456");

        // Assert
        effectiveTenantId.Should().Be("original-tenant-456");
    }

    [Fact]
    public void GetEffectiveTenantId_ShouldReturnNull_WhenBothAreNull()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationTenantId = null,
            IsOperationalContext = false
        };

        // Act
        var effectiveTenantId = context.GetEffectiveTenantId(null);

        // Assert
        effectiveTenantId.Should().BeNull();
    }

    [Fact]
    public void GetEffectiveClientId_ShouldReturnOperationClientId_WhenSet()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationClientId = "operation-client-789",
            IsOperationalContext = true
        };

        // Act
        var effectiveClientId = context.GetEffectiveClientId("original-client-012");

        // Assert
        effectiveClientId.Should().Be("operation-client-789");
    }

    [Fact]
    public void GetEffectiveClientId_ShouldReturnOriginalClientId_WhenOperationClientIdIsNull()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationClientId = null,
            IsOperationalContext = false
        };

        // Act
        var effectiveClientId = context.GetEffectiveClientId("original-client-012");

        // Assert
        effectiveClientId.Should().Be("original-client-012");
    }

    [Fact]
    public void GetEffectiveClientId_ShouldReturnNull_WhenBothAreNull()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationClientId = null,
            IsOperationalContext = false
        };

        // Act
        var effectiveClientId = context.GetEffectiveClientId(null);

        // Assert
        effectiveClientId.Should().BeNull();
    }

    [Fact]
    public void OperationalContext_ShouldInitializeWithDefaultValues()
    {
        // Act
        var context = new OperationalContext();

        // Assert
        context.OperationTenantId.Should().BeNull();
        context.OperationClientId.Should().BeNull();
        context.IsOperationalContext.Should().BeFalse();
    }

    [Fact]
    public void OperationalContext_ShouldAllowPropertySetting()
    {
        // Arrange
        var context = new OperationalContext();

        // Act
        context.OperationTenantId = "tenant-123";
        context.OperationClientId = "client-456";
        context.IsOperationalContext = true;

        // Assert
        context.OperationTenantId.Should().Be("tenant-123");
        context.OperationClientId.Should().Be("client-456");
        context.IsOperationalContext.Should().BeTrue();
    }

    [Fact]
    public void GetEffectiveTenantId_WithOperationalContext_ShouldPrioritizeOperationalId()
    {
        // Arrange
        var context = new OperationalContext
        {
            OperationTenantId = "operational-tenant",
            OperationClientId = "operational-client",
            IsOperationalContext = true
        };

        // Act
        var tenantId = context.GetEffectiveTenantId("original-tenant");
        var clientId = context.GetEffectiveClientId("original-client");

        // Assert
        tenantId.Should().Be("operational-tenant");
        clientId.Should().Be("operational-client");
        context.IsOperationalContext.Should().BeTrue();
    }
}