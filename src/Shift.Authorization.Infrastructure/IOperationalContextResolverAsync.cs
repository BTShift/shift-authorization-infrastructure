using Microsoft.AspNetCore.Http;

namespace Shift.Authorization.Infrastructure;

/// <summary>
/// Defines the async contract for resolving operational context from HTTP headers
/// with database validation support
/// </summary>
public interface IOperationalContextResolverAsync
{
    /// <summary>
    /// Asynchronously resolves the operational context from the HTTP request headers and authorization context
    /// </summary>
    /// <param name="httpContext">The current HTTP context containing request headers</param>
    /// <param name="authContext">The current authorization context for the user</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>The resolved operational context</returns>
    Task<OperationalContext> ResolveContextAsync(
        HttpContext httpContext,
        IAuthorizationContext authContext,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously validates whether the current user has access to operate on the specified tenant/client
    /// </summary>
    /// <param name="targetTenantId">The target tenant ID from X-Operation-Tenant-Id header</param>
    /// <param name="targetClientId">The target client ID from X-Operation-Client-Id header</param>
    /// <param name="authContext">The current authorization context</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if the user has operational access to the specified context</returns>
    Task<bool> ValidateOperationalAccessAsync(
        string? targetTenantId,
        string? targetClientId,
        IAuthorizationContext authContext,
        CancellationToken cancellationToken = default);
}