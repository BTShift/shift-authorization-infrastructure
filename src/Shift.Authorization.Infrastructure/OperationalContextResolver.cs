using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

#pragma warning disable CA1848 // Use LoggerMessage delegates for better performance

namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Implementation of operational context resolver that handles HTTP header-based context switching
/// for SuperAdmin and TenantAdmin users to operate on behalf of different tenants/clients
/// </summary>
public class OperationalContextResolver : IOperationalContextResolver
{
    private readonly ILogger<OperationalContextResolver> _logger;

    public OperationalContextResolver(ILogger<OperationalContextResolver> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <inheritdoc/>
    public OperationalContext ResolveContext(HttpContext httpContext, IAuthorizationContext authContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authContext);

        var context = new OperationalContext();

        // Extract headers
        var targetTenantId = ExtractHeader(httpContext, OperationalContextHeaders.TenantId);
        var targetClientId = ExtractHeader(httpContext, OperationalContextHeaders.ClientId);

        // Check if any operational headers are present
        if (string.IsNullOrEmpty(targetTenantId) && string.IsNullOrEmpty(targetClientId))
        {
            _logger.LogDebug("No operational context headers found");
            context.IsOperationalContext = false;
            return context;
        }

        // Validate access based on user type
        if (!ValidateOperationalAccess(targetTenantId, targetClientId, authContext))
        {
            _logger.LogWarning(
                "Unauthorized operational context attempt by user {UserId} of type {UserType} for tenant {TenantId} and client {ClientId}",
                authContext.UserId, authContext.UserType, targetTenantId, targetClientId);

            throw new UnauthorizedAccessException(
                $"User {authContext.UserId} is not authorized to perform operations in the specified context");
        }

        // Set the operational context
        context.OperationTenantId = targetTenantId;
        context.OperationClientId = targetClientId;
        context.IsOperationalContext = true;

        _logger.LogInformation(
            "Operational context resolved for user {UserId}: TenantId={TenantId}, ClientId={ClientId}",
            authContext.UserId, targetTenantId, targetClientId);

        return context;
    }

    /// <inheritdoc/>
    public bool ValidateOperationalAccess(string? targetTenantId, string? targetClientId, IAuthorizationContext authContext)
    {
        ArgumentNullException.ThrowIfNull(authContext);

        // Apply security rules based on user type
        switch (authContext.UserType)
        {
            case UserType.SuperAdmin:
                // SuperAdmin can set both X-Operation-Tenant-Id and X-Operation-Client-Id
                _logger.LogDebug("SuperAdmin {UserId} validated for operational context", authContext.UserId);
                return true;

            case UserType.TenantAdmin:
                // TenantAdmin can only set X-Operation-Client-Id within their tenant
                if (!string.IsNullOrEmpty(targetTenantId))
                {
                    // TenantAdmin cannot change tenant context
                    _logger.LogWarning(
                        "TenantAdmin {UserId} attempted to set X-Operation-Tenant-Id",
                        authContext.UserId);
                    return false;
                }

                // If client ID is specified, validate it belongs to the tenant
                if (!string.IsNullOrEmpty(targetClientId))
                {
                    // In a real implementation, this would validate against a database
                    // For now, we'll assume the validation passes if the user has a tenant ID
                    if (string.IsNullOrEmpty(authContext.TenantId))
                    {
                        _logger.LogWarning(
                            "TenantAdmin {UserId} without tenant context attempted to set X-Operation-Client-Id",
                            authContext.UserId);
                        return false;
                    }

                    _logger.LogDebug(
                        "TenantAdmin {UserId} validated for client {ClientId} operation within tenant {TenantId}",
                        authContext.UserId, targetClientId, authContext.TenantId);
                    return true;
                }

                // No operational context headers specified
                return true;

            case UserType.ClientUser:
                // ClientUser cannot use operational context headers
                if (!string.IsNullOrEmpty(targetTenantId) || !string.IsNullOrEmpty(targetClientId))
                {
                    _logger.LogWarning(
                        "ClientUser {UserId} attempted to use operational context headers",
                        authContext.UserId);
                    return false;
                }
                return true;

            default:
                _logger.LogError("Unknown user type: {UserType}", authContext.UserType);
                return false;
        }
    }

    /// <summary>
    /// Extracts a header value from the HTTP request
    /// </summary>
    private static string? ExtractHeader(HttpContext httpContext, string headerName)
    {
        if (httpContext.Request.Headers.TryGetValue(headerName, out var headerValue))
        {
            var value = headerValue.ToString();
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
        return null;
    }
}