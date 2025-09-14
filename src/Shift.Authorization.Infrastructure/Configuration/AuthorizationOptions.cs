namespace Shift.Authorization.Infrastructure.Configuration;

/// <summary>
/// Configuration options for the Shift Authorization Infrastructure
/// </summary>
public class AuthorizationOptions
{
    /// <summary>
    /// Gets or sets whether operational context headers are enabled
    /// </summary>
    public bool EnableOperationalContext { get; set; } = true;

    /// <summary>
    /// Gets or sets the list of permission scope mappings
    /// </summary>
    public List<PermissionScopeMapping> PermissionMappings { get; set; } = new();

    /// <summary>
    /// Gets or sets the JWT validation key for token validation
    /// </summary>
    public string? JwtValidationKey { get; set; }

    /// <summary>
    /// Gets or sets the JWT issuer for token validation
    /// </summary>
    public string? JwtIssuer { get; set; }

    /// <summary>
    /// Gets or sets the JWT audience for token validation
    /// </summary>
    public string? JwtAudience { get; set; }

    /// <summary>
    /// Gets or sets whether to validate JWT issuer
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to validate JWT audience
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to validate JWT lifetime
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to require HTTPS for JWT validation
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Gets or sets the clock skew for JWT validation
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets whether to include detailed error messages in responses
    /// </summary>
    public bool IncludeErrorDetails { get; set; }

    /// <summary>
    /// Gets or sets whether async operational context resolution is enabled
    /// </summary>
    public bool EnableAsyncOperationalContextResolution { get; set; }

    /// <summary>
    /// Gets or sets whether token validation caching is enabled
    /// </summary>
    public bool EnableTokenCaching { get; set; } = true;

    /// <summary>
    /// Gets or sets the priority for operational context resolution (Sync or Async first)
    /// </summary>
    public OperationalContextPriority OperationalContextPriority { get; set; } = OperationalContextPriority.SyncFirst;

    /// <summary>
    /// Gets or sets the maximum number of failed authentication attempts before rate limiting
    /// </summary>
    public int MaxFailedAuthAttempts { get; set; } = 5;

    /// <summary>
    /// Gets or sets the time window for tracking failed authentication attempts
    /// </summary>
    public TimeSpan FailedAuthTimeWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the maximum size for JWT tokens (to prevent header size issues)
    /// </summary>
    public int MaxTokenSize { get; set; } = 8192; // 8KB default
}

/// <summary>
/// Defines the priority for operational context resolution
/// </summary>
public enum OperationalContextPriority
{
    /// <summary>
    /// Try synchronous resolver first, then async
    /// </summary>
    SyncFirst,

    /// <summary>
    /// Try asynchronous resolver first, then sync
    /// </summary>
    AsyncFirst
}

/// <summary>
/// Represents a mapping between a permission and its required authorization scope
/// </summary>
public class PermissionScopeMapping
{
    /// <summary>
    /// Gets or sets the permission name
    /// </summary>
    public required string Permission { get; set; }

    /// <summary>
    /// Gets or sets the required authorization scope
    /// </summary>
    public required AuthorizationScope RequiredScope { get; set; }

    /// <summary>
    /// Gets or sets an optional description for the permission
    /// </summary>
    public string? Description { get; set; }
}