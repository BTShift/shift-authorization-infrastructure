using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Shift.Authorization.Infrastructure.Configuration;
using Shift.Authorization.Infrastructure.Middleware;

namespace Shift.Authorization.Infrastructure.Extensions;

/// <summary>
/// Extension methods for configuring Shift Authorization Infrastructure services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Shift Authorization Infrastructure services to the dependency injection container
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configure">Optional configuration action</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddShiftAuthorization(
        this IServiceCollection services,
        Action<AuthorizationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Configure authorization options
        var options = new AuthorizationOptions();
        configure?.Invoke(options);

        services.Configure<AuthorizationOptions>(opt =>
        {
            opt.EnableOperationalContext = options.EnableOperationalContext;
            opt.PermissionMappings = options.PermissionMappings;
            opt.JwtValidationKey = options.JwtValidationKey;
            opt.JwtIssuer = options.JwtIssuer;
            opt.JwtAudience = options.JwtAudience;
            opt.ValidateIssuer = options.ValidateIssuer;
            opt.ValidateAudience = options.ValidateAudience;
            opt.ValidateLifetime = options.ValidateLifetime;
            opt.RequireHttpsMetadata = options.RequireHttpsMetadata;
            opt.ClockSkew = options.ClockSkew;
            opt.IncludeErrorDetails = options.IncludeErrorDetails;
            opt.EnableAsyncOperationalContextResolution = options.EnableAsyncOperationalContextResolution;
        });

        // Register core authorization services
        services.TryAddScoped<AuthorizationContextService>();
        services.TryAddScoped<IAuthorizationContext>(provider =>
        {
            var contextService = provider.GetRequiredService<AuthorizationContextService>();
            return contextService.Context ?? throw new InvalidOperationException(
                "Authorization context is not available. Ensure the AuthorizationContextMiddleware is configured in the pipeline.");
        });

        // Register scope resolver
        services.TryAddSingleton<IScopeResolver, ScopeResolver>();

        // Register operational context resolvers if enabled
        if (options.EnableOperationalContext)
        {
            services.TryAddScoped<IOperationalContextResolver, OperationalContextResolver>();

            if (options.EnableAsyncOperationalContextResolution)
            {
                services.TryAddScoped<IOperationalContextResolverAsync, OperationalContextResolverAsync>();
            }
        }

        // Register authorization service
        services.TryAddScoped<ScopeBasedAuthorizationService>();

        // Register memory cache for token caching if not already registered
        if (options.EnableTokenCaching)
        {
            services.AddMemoryCache();
        }

        // Register rate limiter if rate limiting is enabled
        if (options.MaxFailedAuthAttempts > 0)
        {
            services.TryAddSingleton<AuthenticationRateLimiter>();
        }

        return services;
    }


    /// <summary>
    /// Adds a custom permission scope mapping
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="permission">The permission name</param>
    /// <param name="scope">The required authorization scope</param>
    /// <param name="description">Optional description</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPermissionScopeMapping(
        this IServiceCollection services,
        string permission,
        AuthorizationScope scope,
        string? description = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        services.Configure<AuthorizationOptions>(options =>
        {
            options.PermissionMappings.Add(new Configuration.PermissionScopeMapping
            {
                Permission = permission,
                RequiredScope = scope,
                Description = description
            });
        });

        return services;
    }

    /// <summary>
    /// Configures JWT validation parameters for authorization
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="validationKey">The JWT validation key</param>
    /// <param name="issuer">The JWT issuer</param>
    /// <param name="audience">The JWT audience</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection ConfigureJwtValidation(
        this IServiceCollection services,
        string validationKey,
        string? issuer = null,
        string? audience = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(validationKey);

        services.Configure<AuthorizationOptions>(options =>
        {
            options.JwtValidationKey = validationKey;
            options.JwtIssuer = issuer;
            options.JwtAudience = audience;
            options.ValidateIssuer = !string.IsNullOrEmpty(issuer);
            options.ValidateAudience = !string.IsNullOrEmpty(audience);
        });

        return services;
    }
}

/// <summary>
/// Extension methods for configuring the application pipeline with Shift Authorization
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the Shift Authorization middleware to the application pipeline
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <returns>The application builder for chaining</returns>
    public static IApplicationBuilder UseShiftAuthorization(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Add the authorization context middleware
        app.UseMiddleware<AuthorizationContextMiddleware>();

        return app;
    }

}