# PasswordHasher

A modern, security-focused password hashing library for .NET.

[![NuGet](https://img.shields.io/nuget/v/PasswordHasher.PBKDF2.svg)](https://www.nuget.org/packages/PasswordHasher.PBKDF2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- PBKDF2 implementation with a self-contained hash format
- DI-friendly with Microsoft.Extensions.DependencyInjection
- Timing-safe verification and fake verification
- Migration-ready: old hashes keep working when parameters change
- Static facade for scripts and tests
- No hidden dependencies in the abstractions package

## Packages

| Package                     | Description                                   |
|-----------------------------|-----------------------------------------------|
| PasswordHasher.Abstractions | Interfaces and result types. No dependencies. |
| PasswordHasher.PBKDF2       | PBKDF2 implementation with DI support.        |

## Install

dotnet add package PasswordHasher.PBKDF2

The PasswordHasher.Abstractions package is pulled in transitively. If your
business logic only needs the interface, reference PasswordHasher.Abstractions
directly.

## Quick start

Register in DI:

```csharp
builder.Services.AddPasswordHasher(builder.Configuration);
```

appsettings.json:

```json
{
  "PasswordHasher": {
    "Algorithm": "SHA256",
    "IterationCount": 600000,
    "SaltSize": 16,
    "HashSize": 32
  }
}
```

Inject IPasswordHasher:

```csharp
public sealed class AuthService(IPasswordHasher hasher)
{
public string Register(string password) => hasher.Hash(password);

    public bool Login(string password, string storedHash)
    {
        var result = hasher.Verify(password, storedHash);

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            // Rehash and persist the new value.
        }

        return result != PasswordVerificationResult.Failed;
    }

}
```

## Documentation

- PasswordHasher.Abstractions — interfaces and result types.
- PasswordHasher.PBKDF2 — PBKDF2 implementation, DI, and hash format.

## Hash format

```
$pbkdf2-<algorithm>$v=1$i=<iterations>,l=<hashLength>$<base64_salt>$<base64_hash>
```

The format is self-contained: algorithm, iteration count, salt, and hash
length are stored inside the hash string. Existing hashes keep working after
options change, and SuccessRehashNeeded signals when to upgrade them.

## Security

- Random salt via RandomNumberGenerator.GetBytes.
- Constant-time comparison via CryptographicOperations.FixedTimeEquals.
- Timing-safe fake verification via IMigratingPasswordHasher.FakeVerify.
- OWASP 2024 defaults: SHA256 with 600,000 iterations.
- Rehash support for increasing parameters over time.

## Repository layout

```
PasswordHasher/
├── LICENSE
├── README.md
├── PasswordHasher.sln
├── src/
│   ├── PasswordHasher.Abstractions/
│   │   ├── PasswordHasher.Abstractions.csproj
│   │   ├── IPasswordHasher.cs
│   │   ├── IMigratingPasswordHasher.cs
│   │   ├── PasswordVerificationResult.cs
│   │   └── README.md
│   └── PasswordHasher.PBKDF2/
│       ├── PasswordHasher.PBKDF2.csproj
│       ├── PasswordHasher.cs
│       ├── PasswordHasherOptions.cs
│       ├── StaticPasswordHasher.cs
│       ├── ServiceCollectionExtensions.cs
│       └── README.md
└── tests/
    └── PasswordHasher.Tests/
        └── ...
```

## Building

```
dotnet build
dotnet test
dotnet pack -c Release
```

Packed .nupkg files are placed in the artifacts folder if you configure
output. Otherwise, use:

```
dotnet pack src/PasswordHasher.PBKDF2 -c Release -o artifacts
```

## Requirements

- .NET 10 or later.
- C# 12+ (for the library). Consumers may use any supported C# version.

## Contributing

Issues and pull requests are welcome. For security vulnerabilities, please
open a private security advisory or contact the maintainer directly.

## License

MIT — see LICENSE for details.