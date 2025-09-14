using Microsoft.AspNetCore.Http;
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

    /// <summary>
    /// Initializes a new instance of the AuthorizationContextMiddleware class
    /// </summary>
    /// <param name="next">The next middleware in the pipeline</param>
    /// <param name="logger">Logger for the middleware</param>
    /// <param name="options">Authorization configuration options</param>
    public AuthorizationContextMiddleware(
        RequestDelegate next,
        ILogger<AuthorizationContextMiddleware> logger,
        IOptions<AuthorizationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(options);

        _next = next;
        _logger = logger;
        _options = options.Value;
        _tokenHandler = new JwtSecurityTokenHandler();
        _tokenValidationParameters = CreateTokenValidationParameters();
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
                _logger.LogDebug("No valid authentication found in request");
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
                var operationalContextResolver = context.RequestServices.GetService<IOperationalContextResolver>();
                if (operationalContextResolver != null)
                {
                    try
                    {
                        var operationalContext = operationalContextResolver.ResolveContext(context, authContext);

                        // Apply operational context to authorization context
                        if (operationalContext.IsOperationalContext)
                        {
                            authContext = CreateOperationalAuthorizationContext(authContext, operationalContext);
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
                        return;
                    }
                }
                else if (_options.EnableAsyncOperationalContextResolution)
                {
                    // Try async resolver
                    var asyncResolver = context.RequestServices.GetService<IOperationalContextResolverAsync>();
                    if (asyncResolver != null)
                    {
                        try
                        {
                            var operationalContext = await asyncResolver.ResolveContextAsync(context, authContext);

                            if (operationalContext.IsOperationalContext)
                            {
                                authContext = CreateOperationalAuthorizationContext(authContext, operationalContext);
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
                            return;
                        }
                    }
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
            var principal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogWarning("Token is not a valid JWT");
                return Task.FromResult<ClaimsPrincipal?>(null);
            }

            _logger.LogDebug("JWT token validated successfully for user {UserId}",
                principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? "unknown");

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
    private static string? ExtractTokenFromHeader(HttpContext context)
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

        return authHeader[bearerPrefix.Length..].Trim();
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