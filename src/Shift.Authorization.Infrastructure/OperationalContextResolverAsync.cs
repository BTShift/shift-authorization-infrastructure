using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

#pragma warning disable CA1848 // Use LoggerMessage delegates for better performance

namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Async implementation of operational context resolver with database validation support
/// </summary>
public class OperationalContextResolverAsync : IOperationalContextResolverAsync
{
    private readonly ILogger<OperationalContextResolverAsync> _logger;
    private readonly IClientTenantValidator? _clientTenantValidator;

    public OperationalContextResolverAsync(
        ILogger<OperationalContextResolverAsync> logger,
        IClientTenantValidator? clientTenantValidator = null)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
        _clientTenantValidator = clientTenantValidator;
    }

    /// <inheritdoc/>
    public async Task<OperationalContext> ResolveContextAsync(
        HttpContext httpContext,
        IAuthorizationContext authContext,
        CancellationToken cancellationToken = default)
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
        if (!await ValidateOperationalAccessAsync(targetTenantId, targetClientId, authContext, cancellationToken))
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
    public async Task<bool> ValidateOperationalAccessAsync(
        string? targetTenantId,
        string? targetClientId,
        IAuthorizationContext authContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authContext);

        // Apply security rules based on user type
        switch (authContext.UserType)
        {
            case UserType.SuperAdmin:
                // SuperAdmin can set both headers, but validate existence if validator is available
                if (_clientTenantValidator != null)
                {
                    if (!string.IsNullOrEmpty(targetTenantId))
                    {
                        var tenantExists = await _clientTenantValidator.TenantExistsAsync(targetTenantId, cancellationToken);
                        if (!tenantExists)
                        {
                            _logger.LogWarning("SuperAdmin {UserId} attempted to access non-existent tenant {TenantId}",
                                authContext.UserId, targetTenantId);
                            return false;
                        }
                    }

                    if (!string.IsNullOrEmpty(targetClientId))
                    {
                        var clientExists = await _clientTenantValidator.ClientExistsAsync(targetClientId, cancellationToken);
                        if (!clientExists)
                        {
                            _logger.LogWarning("SuperAdmin {UserId} attempted to access non-existent client {ClientId}",
                                authContext.UserId, targetClientId);
                            return false;
                        }
                    }
                }

                _logger.LogDebug("SuperAdmin {UserId} validated for operational context", authContext.UserId);
                return true;

            case UserType.TenantAdmin:
                // TenantAdmin cannot change tenant context
                if (!string.IsNullOrEmpty(targetTenantId))
                {
                    _logger.LogWarning("TenantAdmin {UserId} attempted to set X-Operation-Tenant-Id", authContext.UserId);
                    return false;
                }

                // Validate client belongs to tenant
                if (!string.IsNullOrEmpty(targetClientId))
                {
                    if (string.IsNullOrEmpty(authContext.TenantId))
                    {
                        _logger.LogWarning(
                            "TenantAdmin {UserId} without tenant context attempted to set X-Operation-Client-Id",
                            authContext.UserId);
                        return false;
                    }

                    // Use validator if available to check client-tenant relationship
                    if (_clientTenantValidator != null)
                    {
                        var isValid = await _clientTenantValidator.ValidateClientBelongsToTenantAsync(
                            targetClientId, authContext.TenantId, cancellationToken);

                        if (!isValid)
                        {
                            _logger.LogWarning(
                                "TenantAdmin {UserId} attempted to access client {ClientId} outside their tenant {TenantId}",
                                authContext.UserId, targetClientId, authContext.TenantId);
                            return false;
                        }
                    }

                    _logger.LogDebug(
                        "TenantAdmin {UserId} validated for client {ClientId} operation within tenant {TenantId}",
                        authContext.UserId, targetClientId, authContext.TenantId);
                    return true;
                }

                return true;

            case UserType.ClientUser:
                // ClientUser cannot use operational context headers
                if (!string.IsNullOrEmpty(targetTenantId) || !string.IsNullOrEmpty(targetClientId))
                {
                    _logger.LogWarning("ClientUser {UserId} attempted to use operational context headers", authContext.UserId);
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