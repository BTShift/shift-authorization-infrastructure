# Basic Web API Example

This example demonstrates the basic usage of Shift Authorization Infrastructure in a minimal Web API.

## Features Demonstrated

- Basic JWT authentication setup
- Permission-based authorization
- Scope-based access control (Platform, Tenant, Own)
- Tenant and client access validation
- Public and protected endpoints

## Getting Started

1. **Run the application:**
   ```bash
   dotnet run
   ```

2. **Access Swagger UI:**
   - Navigate to `https://localhost:5001/swagger` (or the URL shown in console)

## Testing the API

### 1. Generate a JWT Token

You can use this simple JWT token generator or create your own:

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var tokenHandler = new JwtSecurityTokenHandler();
var key = Encoding.UTF8.GetBytes("ThisIsAVerySecretKeyForExamplePurposesOnlyWithAtLeast256Bits!");

var claims = new List<Claim>
{
    new(JwtRegisteredClaimNames.Sub, "user123"),
    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    new("user_type", "SuperAdmin"), // or "TenantAdmin", "ClientUser"
    new("tenant_id", "tenant456"),
    new("client_id", "client789"),
    new("permission", "admin:read"),
    new("permission", "tenant:read"),
    new("permission", "client:write")
};

var tokenDescriptor = new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(claims),
    Expires = DateTime.UtcNow.AddMinutes(60),
    Issuer = "shift-example-issuer",
    Audience = "shift-example-audience",
    SigningCredentials = new SigningCredentials(
        new SymmetricSecurityKey(key),
        SecurityAlgorithms.HmacSha256Signature)
};

var token = tokenHandler.CreateToken(tokenDescriptor);
var tokenString = tokenHandler.WriteToken(token);
Console.WriteLine($"Token: {tokenString}");
```

### 2. Test Endpoints

#### Public Endpoint (No Auth Required)
```bash
curl -X GET "https://localhost:5001/public"
```

#### User Profile (Auth Required)
```bash
curl -X GET "https://localhost:5001/profile" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Admin Users (Platform Permission Required)
```bash
curl -X GET "https://localhost:5001/admin/users" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Tenant Clients (Tenant Access Required)
```bash
curl -X GET "https://localhost:5001/tenant/tenant456/clients" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Create Document (Client Access + Write Permission)
```bash
curl -X POST "https://localhost:5001/client/client789/documents" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Document",
    "content": "This is a test document"
  }'
```

## User Types and Their Capabilities

### SuperAdmin
- Can access any tenant/client
- Has all permissions at Platform scope
- Example: Platform administrators

### TenantAdmin
- Can access only their assigned tenant
- Cannot access Platform scope operations
- Can access Tenant and Own scopes
- Example: Company administrators

### ClientUser
- Can access only their assigned client
- Limited to Own scope operations
- Example: End users

## Permission Examples

The API demonstrates several permission patterns:

- `admin:read` - Platform-level admin read access
- `tenant:read` - Tenant-level read access
- `client:write` - Client-level write access

## Scope Hierarchy

1. **Platform** - Highest level, typically for system administrators
2. **Tenant** - Organization level, for tenant administrators
3. **Own** - User level, for end users accessing their own data

## Error Responses

- **401 Unauthorized** - Missing or invalid JWT token
- **403 Forbidden** - Valid token but insufficient permissions
- **400 Bad Request** - Invalid request format

## Configuration Options

The authorization system can be configured in `Program.cs`:

```csharp
builder.Services.AddShiftAuthorization(options =>
{
    options.JwtValidationKey = "your-secret-key";
    options.JwtIssuer = "your-issuer";
    options.JwtAudience = "your-audience";
    options.EnableOperationalContext = true; // For cross-tenant operations
    options.IncludeErrorDetails = true; // For development
});
```