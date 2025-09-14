using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shift.Authorization.Infrastructure.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

#pragma warning disable CA1848 // Use LoggerMessage delegates for better performance

namespace Shift.Authorization.Infrastructure.Middleware;

/// <summary>
/// Middleware that resolves and injects IAuthorizationContext from JWT and operational headers
/// into the request pipeline for authorization throughout the application
/// </summary>
public class AuthorizationContextMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthorizationContextMiddleware> _logger;
    private readonly AuthorizationOptions _options;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly TokenValidationParameters _tokenValidationParameters;
    private readonly IMemoryCache? _tokenCache;

    /// <summary>
    /// Initializes a new instance of the AuthorizationContextMiddleware class
    /// </summary>
    /// <param name="next">The next middleware in the pipeline</param>
    /// <param name="logger">Logger for the middleware</param>
    /// <param name="options">Authorization configuration options</param>
    /// <param name="tokenCache">Optional memory cache for token validation caching</param>
    public AuthorizationContextMiddleware(
        RequestDelegate next,
        ILogger<AuthorizationContextMiddleware> logger,
        IOptions<AuthorizationOptions> options,
        IMemoryCache? tokenCache = null)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(options);

        _next = next;
        _logger = logger;
        _options = options.Value;
        _tokenHandler = new JwtSecurityTokenHandler();
        _tokenValidationParameters = CreateTokenValidationParameters();
        _tokenCache = tokenCache;
    }

    /// <summary>
    /// Invokes the middleware to process the HTTP request
    /// </summary>
    /// <param name="context">The HTTP context</param>
    /// <returns>A task representing the asynchronous operation</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            // Extract and validate JWT token
            var claimsPrincipal = await ExtractClaimsPrincipalAsync(context);

            if (claimsPrincipal == null)
            {
                // No valid authentication - proceed without authorization context
                _logger.LogDebug("No valid authentication found in request for path {Path}", context.Request.Path);
                await _next(context);
                return;
            }

            // Create authorization context from claims
            var authContext = new AuthorizationContext(claimsPrincipal);

            // Apply custom permission mappings if configured
            if (_options.PermissionMappings?.Count > 0)
            {
                ApplyCustomPermissionMappings(authContext);
            }

            // Handle operational context if enabled
            if (_options.EnableOperationalContext)
            {
                authContext = await ResolveOperationalContextAsync(context, authContext);
                if (authContext == null)
                {
                    // Operational context resolution failed with authorization error
                    return;
                }
            }

            // Register authorization context as scoped service
            var authContextService = context.RequestServices.GetRequiredService<AuthorizationContextService>();
            authContextService.SetContext(authContext);

            // Set user principal for standard ASP.NET Core authorization
            context.User = claimsPrincipal;

            // Continue pipeline
            await _next(context);
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            await HandleAuthorizationFailureAsync(context, "Invalid or expired token", StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in authorization middleware");
            await HandleAuthorizationFailureAsync(context, "Authorization processing failed", StatusCodes.Status500InternalServerError);
        }
    }

    /// <summary>
    /// Extracts and validates the claims principal from the JWT token
    /// </summary>
    private Task<ClaimsPrincipal?> ExtractClaimsPrincipalAsync(HttpContext context)
    {
        var token = ExtractTokenFromHeader(context);

        if (string.IsNullOrEmpty(token))
        {
            return Task.FromResult<ClaimsPrincipal?>(null);
        }

        try
        {
            // Check cache first if enabled
            if (_tokenCache != null && _options.EnableTokenCaching)
            {
                var cacheKey = $"jwt_validation_{token.GetHashCode()}";
                if (_tokenCache.TryGetValue<ClaimsPrincipal>(cacheKey, out var cachedPrincipal))
                {
                    _logger.LogDebug("JWT token retrieved from cache for path {Path}", context.Request.Path);
                    return Task.FromResult<ClaimsPrincipal?>(cachedPrincipal);
                }
            }

            var principal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogWarning("Token is not a valid JWT");
                return Task.FromResult<ClaimsPrincipal?>(null);
            }

            // Cache the validated token if caching is enabled
            if (_tokenCache != null && _options.EnableTokenCaching && validatedToken.ValidTo > DateTime.UtcNow)
            {
                var cacheKey = $"jwt_validation_{token.GetHashCode()}";
                var cacheExpiry = validatedToken.ValidTo.Subtract(DateTime.UtcNow);
                if (cacheExpiry > TimeSpan.Zero)
                {
                    _tokenCache.Set(cacheKey, principal, cacheExpiry);
                }
            }

            var subClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var subClaimAlt = principal.FindFirst("sub")?.Value;
            _logger.LogDebug("JWT token validated successfully for user {UserId} (alt: {AltUserId}) on path {Path}. Claims: {Claims}",
                subClaim ?? "unknown",
                subClaimAlt ?? "unknown",
                context.Request.Path,
                string.Join(", ", principal.Claims.Select(c => $"{c.Type}={c.Value}")));

            return Task.FromResult<ClaimsPrincipal?>(principal);
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            throw new SecurityTokenValidationException("Token validation failed", ex);
        }
    }

    /// <summary>
    /// Extracts the JWT token from the Authorization header
    /// </summary>
    private string? ExtractTokenFromHeader(HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader))
        {
            return null;
        }

        const string bearerPrefix = "Bearer ";

        if (!authHeader.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = authHeader[bearerPrefix.Length..].Trim();

        // Check token size to prevent header size issues
        if (token.Length > _options.MaxTokenSize)
        {
            _logger.LogWarning("JWT token exceeds maximum size of {MaxSize} bytes. Token size: {TokenSize}",
                _options.MaxTokenSize, token.Length);
            return null;
        }

        return token;
    }

    /// <summary>
    /// Creates token validation parameters based on configuration
    /// </summary>
    private TokenValidationParameters CreateTokenValidationParameters()
    {
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = _options.ValidateIssuer,
            ValidateAudience = _options.ValidateAudience,
            ValidateLifetime = _options.ValidateLifetime,
            ValidateIssuerSigningKey = !string.IsNullOrEmpty(_options.JwtValidationKey),
            ClockSkew = _options.ClockSkew,
            RequireExpirationTime = true,
            RequireSignedTokens = true
        };

        if (!string.IsNullOrEmpty(_options.JwtValidationKey))
        {
            parameters.IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_options.JwtValidationKey));
        }

        if (_options.ValidateIssuer && !string.IsNullOrEmpty(_options.JwtIssuer))
        {
            parameters.ValidIssuer = _options.JwtIssuer;
        }

        if (_options.ValidateAudience && !string.IsNullOrEmpty(_options.JwtAudience))
        {
            parameters.ValidAudience = _options.JwtAudience;
        }

        return parameters;
    }

    /// <summary>
    /// Applies custom permission mappings from configuration
    /// </summary>
    private void ApplyCustomPermissionMappings(AuthorizationContext authContext)
    {
        // This would modify the internal permission scope mappings
        // Since AuthorizationContext is immutable in current design,
        // we would need to extend it or use a wrapper
        _logger.LogDebug("Applied {Count} custom permission mappings", _options.PermissionMappings.Count);
    }

    /// <summary>
    /// Resolves operational context based on configured priority
    /// </summary>
    private async Task<AuthorizationContext?> ResolveOperationalContextAsync(
        HttpContext context,
        AuthorizationContext authContext)
    {
        OperationalContext? operationalContext = null;

        if (_options.OperationalContextPriority == OperationalContextPriority.AsyncFirst &&
            _options.EnableAsyncOperationalContextResolution)
        {
            // Try async first
            var asyncResolver = context.RequestServices.GetService<IOperationalContextResolverAsync>();
            if (asyncResolver != null)
            {
                try
                {
                    operationalContext = await asyncResolver.ResolveContextAsync(context, authContext);
                    if (operationalContext.IsOperationalContext)
                    {
                        _logger.LogDebug(
                            "Async operational context applied: TenantId={TenantId}, ClientId={ClientId}",
                            operationalContext.OperationTenantId,
                            operationalContext.OperationClientId);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning(ex, "Unauthorized async operational context attempt");
                    await HandleAuthorizationFailureAsync(context, "Unauthorized operational context", StatusCodes.Status403Forbidden);
                    return null;
                }
            }
        }

        // If no operational context from async (or sync first), try sync
        if (operationalContext == null || !operationalContext.IsOperationalContext)
        {
            var syncResolver = context.RequestServices.GetService<IOperationalContextResolver>();
            if (syncResolver != null)
            {
                try
                {
                    operationalContext = syncResolver.ResolveContext(context, authContext);
                    if (operationalContext.IsOperationalContext)
                    {
                        _logger.LogDebug(
                            "Operational context applied: TenantId={TenantId}, ClientId={ClientId}",
                            operationalContext.OperationTenantId,
                            operationalContext.OperationClientId);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning(ex, "Unauthorized operational context attempt");
                    await HandleAuthorizationFailureAsync(context, "Unauthorized operational context", StatusCodes.Status403Forbidden);
                    return null;
                }
            }
        }

        // If still no operational context and async wasn't tried yet, try it now
        if ((operationalContext == null || !operationalContext.IsOperationalContext) &&
            _options.OperationalContextPriority == OperationalContextPriority.SyncFirst &&
            _options.EnableAsyncOperationalContextResolution)
        {
            var asyncResolver = context.RequestServices.GetService<IOperationalContextResolverAsync>();
            if (asyncResolver != null)
            {
                try
                {
                    operationalContext = await asyncResolver.ResolveContextAsync(context, authContext);
                    if (operationalContext.IsOperationalContext)
                    {
                        _logger.LogDebug(
                            "Async operational context applied: TenantId={TenantId}, ClientId={ClientId}",
                            operationalContext.OperationTenantId,
                            operationalContext.OperationClientId);
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning(ex, "Unauthorized async operational context attempt");
                    await HandleAuthorizationFailureAsync(context, "Unauthorized operational context", StatusCodes.Status403Forbidden);
                    return null;
                }
            }
        }

        // Apply operational context if found
        if (operationalContext != null && operationalContext.IsOperationalContext)
        {
            return CreateOperationalAuthorizationContext(authContext, operationalContext);
        }

        return authContext;
    }

    /// <summary>
    /// Creates a new authorization context with operational context applied
    /// </summary>
    private static AuthorizationContext CreateOperationalAuthorizationContext(
        AuthorizationContext originalContext,
        OperationalContext operationalContext)
    {
        // Create a new context with operational tenant/client IDs
        var tenantId = operationalContext.OperationTenantId ?? originalContext.TenantId;
        var clientId = operationalContext.OperationClientId ?? originalContext.ClientId;

        return new AuthorizationContext(
            originalContext.UserId,
            tenantId,
            clientId,
            originalContext.UserType,
            originalContext.Permissions);
    }

    /// <summary>
    /// Handles authorization failures by writing appropriate error response
    /// </summary>
    private async Task HandleAuthorizationFailureAsync(HttpContext context, string message, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";

        var response = new
        {
            error = statusCode switch
            {
                StatusCodes.Status401Unauthorized => "unauthorized",
                StatusCodes.Status403Forbidden => "forbidden",
                _ => "error"
            },
            message = _options.IncludeErrorDetails ? message : "Authorization failed",
            timestamp = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(response);
        await context.Response.WriteAsync(json);
    }
}

/// <summary>
/// Scoped service to hold the authorization context for the current request
/// </summary>
public class AuthorizationContextService
{
    private IAuthorizationContext? _context;

    /// <summary>
    /// Gets the current authorization context
    /// </summary>
    public IAuthorizationContext? Context => _context;

    /// <summary>
    /// Sets the authorization context for the current request
    /// </summary>
    internal void SetContext(IAuthorizationContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }
}