using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Shift.Authorization.Infrastructure.Tests;

public class OperationalContextResolverTests
{
    private readonly Mock<ILogger<OperationalContextResolver>> _loggerMock;
    private readonly OperationalContextResolver _resolver;
    private readonly Mock<IAuthorizationContext> _authContextMock;

    public OperationalContextResolverTests()
    {
        _loggerMock = new Mock<ILogger<OperationalContextResolver>>();
        _resolver = new OperationalContextResolver(_loggerMock.Object);
        _authContextMock = new Mock<IAuthorizationContext>();
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new OperationalContextResolver(null!));
    }

    [Fact]
    public void ResolveContext_ShouldThrowArgumentNullException_WhenHttpContextIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _resolver.ResolveContext(null!, _authContextMock.Object));
    }

    [Fact]
    public void ResolveContext_ShouldThrowArgumentNullException_WhenAuthContextIsNull()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _resolver.ResolveContext(httpContext, null!));
    }

    [Fact]
    public void ResolveContext_ShouldReturnNonOperationalContext_WhenNoHeadersProvided()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        _authContextMock.Setup(x => x.UserType).Returns(UserType.SuperAdmin);

        // Act
        var result = _resolver.ResolveContext(httpContext, _authContextMock.Object);

        // Assert
        result.Should().NotBeNull();
        result.IsOperationalContext.Should().BeFalse();
        result.OperationTenantId.Should().BeNull();
        result.OperationClientId.Should().BeNull();
    }

    [Fact]
    public void ResolveContext_SuperAdmin_ShouldAllowBothHeaders()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Tenant-Id"] = "tenant123";
        httpContext.Request.Headers["X-Operation-Client-Id"] = "client456";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.SuperAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("superadmin1");

        // Act
        var result = _resolver.ResolveContext(httpContext, _authContextMock.Object);

        // Assert
        result.Should().NotBeNull();
        result.IsOperationalContext.Should().BeTrue();
        result.OperationTenantId.Should().Be("tenant123");
        result.OperationClientId.Should().Be("client456");
    }

    [Fact]
    public void ResolveContext_SuperAdmin_ShouldAllowOnlyTenantHeader()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Tenant-Id"] = "tenant123";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.SuperAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("superadmin1");

        // Act
        var result = _resolver.ResolveContext(httpContext, _authContextMock.Object);

        // Assert
        result.Should().NotBeNull();
        result.IsOperationalContext.Should().BeTrue();
        result.OperationTenantId.Should().Be("tenant123");
        result.OperationClientId.Should().BeNull();
    }

    [Fact]
    public void ResolveContext_TenantAdmin_ShouldAllowOnlyClientHeader()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Client-Id"] = "client456";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");
        _authContextMock.Setup(x => x.TenantId).Returns("tenant123");

        // Act
        var result = _resolver.ResolveContext(httpContext, _authContextMock.Object);

        // Assert
        result.Should().NotBeNull();
        result.IsOperationalContext.Should().BeTrue();
        result.OperationTenantId.Should().BeNull();
        result.OperationClientId.Should().Be("client456");
    }

    [Fact]
    public void ResolveContext_TenantAdmin_ShouldThrowUnauthorized_WhenTenantHeaderProvided()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Tenant-Id"] = "tenant999";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");
        _authContextMock.Setup(x => x.TenantId).Returns("tenant123");

        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _resolver.ResolveContext(httpContext, _authContextMock.Object));
    }

    [Fact]
    public void ResolveContext_TenantAdmin_ShouldThrowUnauthorized_WhenNoTenantContext()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Client-Id"] = "client456";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");
        _authContextMock.Setup(x => x.TenantId).Returns((string?)null);

        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _resolver.ResolveContext(httpContext, _authContextMock.Object));
    }

    [Fact]
    public void ResolveContext_ClientUser_ShouldThrowUnauthorized_WhenAnyHeaderProvided()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Client-Id"] = "client456";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.ClientUser);
        _authContextMock.Setup(x => x.UserId).Returns("clientuser1");

        // Act & Assert
        Assert.Throws<UnauthorizedAccessException>(() =>
            _resolver.ResolveContext(httpContext, _authContextMock.Object));
    }

    [Fact]
    public void ResolveContext_ShouldTrimHeaderValues()
    {
        // Arrange
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Operation-Tenant-Id"] = "  tenant123  ";
        httpContext.Request.Headers["X-Operation-Client-Id"] = "  client456  ";

        _authContextMock.Setup(x => x.UserType).Returns(UserType.SuperAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("superadmin1");

        // Act
        var result = _resolver.ResolveContext(httpContext, _authContextMock.Object);

        // Assert
        result.OperationTenantId.Should().Be("tenant123");
        result.OperationClientId.Should().Be("client456");
    }

    [Fact]
    public void ValidateOperationalAccess_ShouldThrowArgumentNullException_WhenAuthContextIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _resolver.ValidateOperationalAccess("tenant123", "client456", null!));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("tenant123", null)]
    [InlineData(null, "client456")]
    [InlineData("tenant123", "client456")]
    public void ValidateOperationalAccess_SuperAdmin_ShouldAlwaysReturnTrue(string? tenantId, string? clientId)
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.SuperAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("superadmin1");

        // Act
        var result = _resolver.ValidateOperationalAccess(tenantId, clientId, _authContextMock.Object);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateOperationalAccess_TenantAdmin_ShouldReturnFalse_WhenTenantIdProvided()
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");

        // Act
        var result = _resolver.ValidateOperationalAccess("tenant123", null, _authContextMock.Object);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateOperationalAccess_TenantAdmin_ShouldReturnTrue_WhenOnlyClientIdProvided()
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");
        _authContextMock.Setup(x => x.TenantId).Returns("tenant123");

        // Act
        var result = _resolver.ValidateOperationalAccess(null, "client456", _authContextMock.Object);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateOperationalAccess_TenantAdmin_ShouldReturnFalse_WhenNoTenantContext()
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.TenantAdmin);
        _authContextMock.Setup(x => x.UserId).Returns("tenantadmin1");
        _authContextMock.Setup(x => x.TenantId).Returns((string?)null);

        // Act
        var result = _resolver.ValidateOperationalAccess(null, "client456", _authContextMock.Object);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("tenant123", null)]
    [InlineData(null, "client456")]
    [InlineData("tenant123", "client456")]
    public void ValidateOperationalAccess_ClientUser_ShouldReturnFalse_WhenAnyHeaderProvided(string? tenantId, string? clientId)
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.ClientUser);
        _authContextMock.Setup(x => x.UserId).Returns("clientuser1");

        // Act
        var result = _resolver.ValidateOperationalAccess(tenantId, clientId, _authContextMock.Object);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateOperationalAccess_ClientUser_ShouldReturnTrue_WhenNoHeadersProvided()
    {
        // Arrange
        _authContextMock.Setup(x => x.UserType).Returns(UserType.ClientUser);
        _authContextMock.Setup(x => x.UserId).Returns("clientuser1");

        // Act
        var result = _resolver.ValidateOperationalAccess(null, null, _authContextMock.Object);

        // Assert
        result.Should().BeTrue();
    }
}