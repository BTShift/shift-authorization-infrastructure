using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Shift.Authorization.Infrastructure;
using Shift.Authorization.Infrastructure.Extensions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

// Create a host builder for dependency injection
var builder = Host.CreateDefaultBuilder(args);

builder.ConfigureServices(services =>
{
    // Add Shift Authorization services
    services.AddShiftAuthorization(options =>
    {
        // JWT Configuration for standalone console app
        options.JwtValidationKey = "ThisIsAVerySecretKeyForConsoleAppExampleWithAtLeast256Bits!";
        options.JwtIssuer = "shift-console-issuer";
        options.JwtAudience = "shift-console-audience";
        options.ValidateIssuer = true;
        options.ValidateAudience = true;
        options.ValidateLifetime = true;

        // Disable operational context for this standalone example
        options.EnableOperationalContext = false;
    });

    // Register our demo services
    services.AddScoped<IDemoService, DemoService>();
    services.AddScoped<IJwtTokenService, JwtTokenService>();
    services.AddScoped<AuthorizationDemoRunner>();
});

var host = builder.Build();

// Run the authorization demos
using var scope = host.Services.CreateScope();
var demoRunner = scope.ServiceProvider.GetRequiredService<AuthorizationDemoRunner>();
await demoRunner.RunAllDemosAsync();

Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();

// Demo service interfaces and implementations
public interface IDemoService
{
    Task<string> GetPublicDataAsync();
    Task<string> GetTenantDataAsync(string tenantId, IAuthorizationContext context);
    Task<string> GetClientDataAsync(string clientId, IAuthorizationContext context);
    Task<string> GenerateReportAsync(string reportType, IAuthorizationContext context);
}

public class DemoService : IDemoService
{
    private readonly ILogger<DemoService> _logger;

    public DemoService(ILogger<DemoService> logger)
    {
        _logger = logger;
    }

    public Task<string> GetPublicDataAsync()
    {
        return Task.FromResult("This is public data accessible to everyone");
    }

    public Task<string> GetTenantDataAsync(string tenantId, IAuthorizationContext context)
    {
        if (!context.CanAccessTenant(tenantId))
        {
            throw new UnauthorizedAccessException($"Cannot access tenant {tenantId}");
        }

        if (!context.HasPermission("tenant:read", AuthorizationScope.Tenant))
        {
            throw new UnauthorizedAccessException("Insufficient permissions to read tenant data");
        }

        _logger.LogInformation("User {UserId} accessed tenant {TenantId}", context.UserId, tenantId);
        return Task.FromResult($"Tenant data for {tenantId}: [confidential tenant information]");
    }

    public Task<string> GetClientDataAsync(string clientId, IAuthorizationContext context)
    {
        if (!context.CanAccessClient(clientId))
        {
            throw new UnauthorizedAccessException($"Cannot access client {clientId}");
        }

        if (!context.HasPermission("client:read", AuthorizationScope.Own))
        {
            throw new UnauthorizedAccessException("Insufficient permissions to read client data");
        }

        _logger.LogInformation("User {UserId} accessed client {ClientId}", context.UserId, clientId);
        return Task.FromResult($"Client data for {clientId}: [confidential client information]");
    }

    public Task<string> GenerateReportAsync(string reportType, IAuthorizationContext context)
    {
        var requiredScope = reportType.ToLowerInvariant() switch
        {
            "platform" => AuthorizationScope.Platform,
            "tenant" => AuthorizationScope.Tenant,
            "client" => AuthorizationScope.Own,
            _ => AuthorizationScope.Own
        };

        if (!context.HasPermission("reports:generate", requiredScope))
        {
            throw new UnauthorizedAccessException($"Insufficient permissions to generate {reportType} reports");
        }

        _logger.LogInformation("User {UserId} generated {ReportType} report", context.UserId, reportType);
        return Task.FromResult($"{reportType.ToUpperInvariant()} Report generated successfully by {context.UserId}");
    }
}

public interface IJwtTokenService
{
    string GenerateToken(string userId, UserType userType, string? tenantId = null, string? clientId = null, params string[] permissions);
    IAuthorizationContext CreateContextFromToken(string token);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly string _secretKey = "ThisIsAVerySecretKeyForConsoleAppExampleWithAtLeast256Bits!";
    private readonly string _issuer = "shift-console-issuer";
    private readonly string _audience = "shift-console-audience";

    public string GenerateToken(string userId, UserType userType, string? tenantId = null, string? clientId = null, params string[] permissions)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_secretKey);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_type", userType.ToString())
        };

        if (!string.IsNullOrEmpty(tenantId))
            claims.Add(new Claim("tenant_id", tenantId));

        if (!string.IsNullOrEmpty(clientId))
            claims.Add(new Claim("client_id", clientId));

        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(60),
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public IAuthorizationContext CreateContextFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_secretKey);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = true,
            ValidAudience = _audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
        return new AuthorizationContext(principal);
    }
}

public class AuthorizationDemoRunner
{
    private readonly IDemoService _demoService;
    private readonly IJwtTokenService _tokenService;
    private readonly ILogger<AuthorizationDemoRunner> _logger;

    public AuthorizationDemoRunner(
        IDemoService demoService,
        IJwtTokenService tokenService,
        ILogger<AuthorizationDemoRunner> logger)
    {
        _demoService = demoService;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task RunAllDemosAsync()
    {
        Console.WriteLine("=== Shift Authorization Infrastructure Console Demo ===\n");

        await RunPublicDataDemoAsync();
        await RunSuperAdminDemoAsync();
        await RunTenantAdminDemoAsync();
        await RunClientUserDemoAsync();
        await RunUnauthorizedAccessDemoAsync();
        await RunPermissionBoundaryDemoAsync();
    }

    private async Task RunPublicDataDemoAsync()
    {
        Console.WriteLine("1. Public Data Access (No Authentication Required)");
        Console.WriteLine("=".PadRight(60, '='));

        var publicData = await _demoService.GetPublicDataAsync();
        Console.WriteLine($"✅ Public data: {publicData}");
        Console.WriteLine();
    }

    private async Task RunSuperAdminDemoAsync()
    {
        Console.WriteLine("2. SuperAdmin Access (Full Platform Access)");
        Console.WriteLine("=".PadRight(60, '='));

        var token = _tokenService.GenerateToken(
            userId: "admin@platform.com",
            userType: UserType.SuperAdmin,
            permissions: new[] { "platform:admin", "tenant:read", "client:read", "reports:generate" }
        );

        var context = _tokenService.CreateContextFromToken(token);

        Console.WriteLine($"User: {context.UserId} ({context.UserType})");

        try
        {
            // SuperAdmin can access any tenant
            var tenantData = await _demoService.GetTenantDataAsync("tenant-123", context);
            Console.WriteLine($"✅ Tenant access: {tenantData}");

            // SuperAdmin can access any client
            var clientData = await _demoService.GetClientDataAsync("client-456", context);
            Console.WriteLine($"✅ Client access: {clientData}");

            // SuperAdmin can generate platform reports
            var platformReport = await _demoService.GenerateReportAsync("platform", context);
            Console.WriteLine($"✅ Platform report: {platformReport}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private async Task RunTenantAdminDemoAsync()
    {
        Console.WriteLine("3. TenantAdmin Access (Limited to Assigned Tenant)");
        Console.WriteLine("=".PadRight(60, '='));

        var token = _tokenService.GenerateToken(
            userId: "admin@tenant123.com",
            userType: UserType.TenantAdmin,
            tenantId: "tenant-123",
            permissions: new[] { "tenant:read", "client:read", "reports:generate" }
        );

        var context = _tokenService.CreateContextFromToken(token);

        Console.WriteLine($"User: {context.UserId} ({context.UserType})");
        Console.WriteLine($"Assigned Tenant: {context.TenantId}");

        try
        {
            // TenantAdmin can access their own tenant
            var tenantData = await _demoService.GetTenantDataAsync("tenant-123", context);
            Console.WriteLine($"✅ Own tenant access: {tenantData}");

            // TenantAdmin can generate tenant reports
            var tenantReport = await _demoService.GenerateReportAsync("tenant", context);
            Console.WriteLine($"✅ Tenant report: {tenantReport}");

            // TenantAdmin cannot access different tenant
            try
            {
                await _demoService.GetTenantDataAsync("tenant-456", context);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("✅ Correctly blocked access to different tenant");
            }

            // TenantAdmin cannot generate platform reports
            try
            {
                await _demoService.GenerateReportAsync("platform", context);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("✅ Correctly blocked platform report generation");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private async Task RunClientUserDemoAsync()
    {
        Console.WriteLine("4. ClientUser Access (Limited to Own Data)");
        Console.WriteLine("=".PadRight(60, '='));

        var token = _tokenService.GenerateToken(
            userId: "user@client456.com",
            userType: UserType.ClientUser,
            tenantId: "tenant-123",
            clientId: "client-456",
            permissions: new[] { "client:read", "reports:generate" }
        );

        var context = _tokenService.CreateContextFromToken(token);

        Console.WriteLine($"User: {context.UserId} ({context.UserType})");
        Console.WriteLine($"Assigned Client: {context.ClientId}");

        try
        {
            // ClientUser can access their own client data
            var clientData = await _demoService.GetClientDataAsync("client-456", context);
            Console.WriteLine($"✅ Own client access: {clientData}");

            // ClientUser can generate client reports
            var clientReport = await _demoService.GenerateReportAsync("client", context);
            Console.WriteLine($"✅ Client report: {clientReport}");

            // ClientUser cannot access different client
            try
            {
                await _demoService.GetClientDataAsync("client-789", context);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("✅ Correctly blocked access to different client");
            }

            // ClientUser cannot access tenant data directly
            try
            {
                await _demoService.GetTenantDataAsync("tenant-123", context);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("✅ Correctly blocked tenant data access");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private async Task RunUnauthorizedAccessDemoAsync()
    {
        Console.WriteLine("5. Unauthorized Access Attempts");
        Console.WriteLine("=".PadRight(60, '='));

        // Create a user with no permissions
        var token = _tokenService.GenerateToken(
            userId: "user@nopermissions.com",
            userType: UserType.ClientUser,
            tenantId: "tenant-123",
            clientId: "client-456"
            // No permissions granted
        );

        var context = _tokenService.CreateContextFromToken(token);

        Console.WriteLine($"User: {context.UserId} ({context.UserType})");
        Console.WriteLine("Permissions: None");

        try
        {
            await _demoService.GetClientDataAsync("client-456", context);
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("✅ Correctly blocked client access without permissions");
        }

        try
        {
            await _demoService.GenerateReportAsync("client", context);
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("✅ Correctly blocked report generation without permissions");
        }

        Console.WriteLine();
    }

    private async Task RunPermissionBoundaryDemoAsync()
    {
        Console.WriteLine("6. Permission Boundary Testing");
        Console.WriteLine("=".PadRight(60, '='));

        var superAdmin = _tokenService.CreateContextFromToken(_tokenService.GenerateToken(
            "superadmin", UserType.SuperAdmin, permissions: new[] { "test:permission" }));

        var tenantAdmin = _tokenService.CreateContextFromToken(_tokenService.GenerateToken(
            "tenantadmin", UserType.TenantAdmin, "tenant-1", permissions: new[] { "test:permission" }));

        var clientUser = _tokenService.CreateContextFromToken(_tokenService.GenerateToken(
            "clientuser", UserType.ClientUser, "tenant-1", "client-1", permissions: new[] { "test:permission" }));

        // Test permission at different scopes
        var testCases = new[]
        {
            (AuthorizationScope.Platform, "Platform"),
            (AuthorizationScope.Tenant, "Tenant"),
            (AuthorizationScope.Own, "Own")
        };

        var users = new[]
        {
            (superAdmin, "SuperAdmin"),
            (tenantAdmin, "TenantAdmin"),
            (clientUser, "ClientUser")
        };

        Console.WriteLine("Permission: 'test:permission' at different scopes:");
        Console.WriteLine();

        foreach (var (scope, scopeName) in testCases)
        {
            Console.WriteLine($"{scopeName} Scope:");
            foreach (var (user, userType) in users)
            {
                var hasPermission = user.HasPermission("test:permission", scope);
                var indicator = hasPermission ? "✅" : "❌";
                Console.WriteLine($"  {indicator} {userType}: {hasPermission}");
            }
            Console.WriteLine();
        }

        await Task.CompletedTask;
    }
}