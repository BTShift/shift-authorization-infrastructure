# Shift.Authorization.Infrastructure

[![NuGet Version](https://img.shields.io/nuget/v/Shift.Authorization.Infrastructure.svg)](https://www.nuget.org/packages/Shift.Authorization.Infrastructure)
[![GitHub Release](https://img.shields.io/github/v/release/BTShift/shift-authorization-infrastructure.svg)](https://github.com/BTShift/shift-authorization-infrastructure/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/BTShift/shift-authorization-infrastructure/publish-package.yml)](https://github.com/BTShift/shift-authorization-infrastructure/actions)

Authorization infrastructure package for BTShift multi-tenant SaaS platform - provides scope-based authorization with operational context support.

## Overview

This library provides the foundational components for implementing a robust, multi-tenant authorization system within the BTShift platform. It defines the core contracts and interfaces needed to build a scope-based authorization system that supports:

- **Multi-tenant isolation**: User and tenant context separation
- **Scope-based permissions**: Fine-grained authorization controls
- **Operational context**: Context-aware authorization decisions
- **Microservice integration**: Seamless integration with gRPC and REST services

## Installation

### Package Manager
```
Install-Package Shift.Authorization.Infrastructure
```

### .NET CLI
```bash
dotnet add package Shift.Authorization.Infrastructure
```

### PackageReference
```xml
<PackageReference Include="Shift.Authorization.Infrastructure" Version="1.0.0" />
```

## Usage

### IAuthorizationContext Interface

The core interface provides access to authorization context:

```csharp
using Shift.Authorization.Infrastructure;

public class MyService
{
    private readonly IAuthorizationContext _authContext;

    public MyService(IAuthorizationContext authContext)
    {
        _authContext = authContext;
    }

    public async Task<bool> CanAccessResource(string resourceId)
    {
        // Check if user has required scope
        if (!_authContext.HasScope("resource.read"))
        {
            return false;
        }

        // Verify tenant access
        var allowedForTenant = await ValidateTenantAccess(
            _authContext.TenantId,
            resourceId
        );

        return allowedForTenant;
    }
}
```

### Context Properties

```csharp
// Access user information
string userId = _authContext.UserId;

// Access tenant information
string tenantId = _authContext.TenantId;

// Check available scopes
IEnumerable<string> scopes = _authContext.Scopes;

// Verify specific scope
bool hasReadAccess = _authContext.HasScope("accounting.invoices.read");
bool hasWriteAccess = _authContext.HasScope("accounting.invoices.write");
```

## Architecture Integration

This package serves as the foundation for the BTShift authorization architecture:

```
┌─────────────────────────┐
│   API Gateway           │
│                         │
│  ┌─────────────────────┐│
│  │ Authorization       ││
│  │ Middleware          ││
│  └─────────────────────┘│
└─────────┬───────────────┘
          │
          ▼
┌─────────────────────────┐
│   Microservices         │
│                         │
│  ┌─────────────────────┐│
│  │ IAuthorizationContext││  ◄── This Package
│  └─────────────────────┘│
└─────────────────────────┘
```

## Scope System Design

The authorization system implements a 3-layer scope hierarchy:

1. **Platform Scope**: `platform.admin`
2. **Service Scope**: `accounting.invoices.read`
3. **Resource Scope**: `accounting.invoices.{invoiceId}.read`

### Scope Examples

```csharp
// Platform-level permissions
_authContext.HasScope("platform.admin");
_authContext.HasScope("platform.support");

// Service-level permissions
_authContext.HasScope("accounting.invoices.read");
_authContext.HasScope("accounting.invoices.write");
_authContext.HasScope("tenant-management.users.read");

// Resource-level permissions (planned)
_authContext.HasScope("accounting.invoices.12345.read");
_authContext.HasScope("client-management.clients.67890.write");
```

## Multi-Tenant Context

The authorization context is tenant-aware:

```csharp
public class TenantAwareService
{
    private readonly IAuthorizationContext _authContext;

    public async Task<Invoice[]> GetInvoicesAsync()
    {
        // Automatically filter by tenant context
        var tenantId = _authContext.TenantId;
        var userId = _authContext.UserId;

        // Ensure user has permission
        if (!_authContext.HasScope("accounting.invoices.read"))
        {
            throw new UnauthorizedAccessException();
        }

        return await _invoiceRepository.GetByTenantAsync(tenantId);
    }
}
```

## Development Roadmap

This foundation package will be extended with:

- **Context Resolution**: HTTP header and JWT token parsing
- **Authorization Middleware**: ASP.NET Core middleware integration
- **gRPC Interceptors**: Automatic context propagation
- **Scope Validation**: Advanced scope matching and validation
- **Audit Integration**: Authorization decision logging

## Contributing

This package is part of the BTShift platform infrastructure. For contribution guidelines, please see the main platform documentation.

## Related Packages

- `Shift.Messaging.Infrastructure` - Message bus integration
- `Shift.ErrorHandling.Infrastructure` - Standardized error handling
- `Shift.Logging.Infrastructure` - Structured logging
- `Shift.MultiTenant.Infrastructure` - Multi-tenant utilities

## License

MIT License. See [LICENSE](LICENSE) for details.
