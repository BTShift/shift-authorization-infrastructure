using Microsoft.AspNetCore.Http;

namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the contract for resolving operational context from HTTP headers
/// that allows SuperAdmin and TenantAdmin users to operate on behalf of different tenants/clients
/// </summary>
public interface IOperationalContextResolver
{
    /// <summary>
    /// Resolves the operational context from the HTTP request headers and authorization context
    /// </summary>
    /// <param name="httpContext">The current HTTP context containing request headers</param>
    /// <param name="authContext">The current authorization context for the user</param>
    /// <returns>The resolved operational context</returns>
    OperationalContext ResolveContext(HttpContext httpContext, IAuthorizationContext authContext);

    /// <summary>
    /// Validates whether the current user has access to operate on the specified tenant/client
    /// </summary>
    /// <param name="targetTenantId">The target tenant ID from X-Operation-Tenant-Id header</param>
    /// <param name="targetClientId">The target client ID from X-Operation-Client-Id header</param>
    /// <param name="authContext">The current authorization context</param>
    /// <returns>True if the user has operational access to the specified context</returns>
    bool ValidateOperationalAccess(string? targetTenantId, string? targetClientId, IAuthorizationContext authContext);
}