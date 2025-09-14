using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Shift.Authorization.Infrastructure.Configuration;
using System.Collections.Concurrent;

#pragma warning disable CA1848 // Use LoggerMessage delegates for better performance

namespace Shift.Authorization.Infrastructure.Middleware;

/// <summary>
/// Provides rate limiting for failed authentication attempts to prevent brute force attacks
/// </summary>
public class AuthenticationRateLimiter
{
    private readonly IMemoryCache _cache;
    private readonly AuthorizationOptions _options;
    private readonly ILogger<AuthenticationRateLimiter> _logger;

    /// <summary>
    /// Initializes a new instance of the AuthenticationRateLimiter class
    /// </summary>
    public AuthenticationRateLimiter(
        IMemoryCache cache,
        AuthorizationOptions options,
        ILogger<AuthenticationRateLimiter> logger)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _cache = cache;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Checks if an identifier (IP, user, etc.) is rate limited
    /// </summary>
    /// <param name="identifier">The identifier to check (e.g., IP address, username)</param>
    /// <returns>True if the identifier is rate limited</returns>
    public bool IsRateLimited(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            return false;

        var cacheKey = $"auth_ratelimit_{identifier}";

        if (_cache.TryGetValue<FailedAttemptTracker>(cacheKey, out var tracker) && tracker != null)
        {
            if (tracker.Count >= _options.MaxFailedAuthAttempts)
            {
                _logger.LogWarning("Authentication rate limit exceeded for {Identifier}. {Count} failed attempts in {Window}",
                    identifier, tracker.Count, _options.FailedAuthTimeWindow);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Records a failed authentication attempt
    /// </summary>
    /// <param name="identifier">The identifier that failed authentication</param>
    public void RecordFailedAttempt(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            return;

        var cacheKey = $"auth_ratelimit_{identifier}";

        var tracker = _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.SlidingExpiration = _options.FailedAuthTimeWindow;
            return new FailedAttemptTracker();
        });

        tracker?.IncrementCount();

        _logger.LogDebug("Failed authentication attempt recorded for {Identifier}. Count: {Count}",
            identifier, tracker?.Count ?? 0);
    }

    /// <summary>
    /// Clears the rate limit for an identifier (e.g., after successful authentication)
    /// </summary>
    /// <param name="identifier">The identifier to clear</param>
    public void ClearRateLimit(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            return;

        var cacheKey = $"auth_ratelimit_{identifier}";
        _cache.Remove(cacheKey);

        _logger.LogDebug("Rate limit cleared for {Identifier}", identifier);
    }

    /// <summary>
    /// Internal class to track failed attempts
    /// </summary>
    private sealed class FailedAttemptTracker
    {
        private int _count;

        public int Count => _count;

        public void IncrementCount()
        {
            Interlocked.Increment(ref _count);
        }
    }
}