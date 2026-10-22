# PasswordHasher.PBKDF2

PBKDF2-based password hasher for .NET with a self-contained hash format,
DI support, and timing-safe verification.

- Self-contained hash string — parameters are stored with the hash
- DI-friendly, configurable via appsettings.json
- CryptographicOperations.FixedTimeEquals for constant-time comparison
- FakeVerify for timing-safe user-enumeration protection
- SuccessRehashNeeded for seamless parameter upgrades

## Install

dotnet add package PasswordHasher.PBKDF2

The PasswordHasher.Abstractions package is pulled in transitively.

## Requirements

- .NET 10 or later.

## Quick start

### With DI (recommended)

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

Then inject IPasswordHasher:

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

### Programmatic configuration

```csharp
builder.Services.AddPasswordHasher(options =>
{
    options.Algorithm = "SHA512";
    options.IterationCount = 210_000;
    options.SaltSize = 32;
    options.HashSize = 64;
});
```

### Custom configuration section

```csharp
builder.Services.AddPasswordHasher(builder.Configuration.GetSection("Auth:PasswordHasher"));
```

### Options

| Property       | Default | Min    | Description                  |
|----------------|---------|--------|------------------------------|
| Algorithm      | SHA256  | —      | SHA1, SHA256, SHA384, SHA512 |
| IterationCount | 600000  | 100000 | Number of PBKDF2 iterations  |
| SaltSize       | 16      | 8      | Salt size in bytes           |
| HashSize       | 32      | 16     | Hash length in bytes         |

### Static facade (scripts and tests)

```csharp
string hash = StaticPasswordHasher.Hash("secret");
var result = StaticPasswordHasher.Verify("secret", hash); // Success

var bad = StaticPasswordHasher.Verify("wrong", hash); // Failed
```

The static facade uses default options and does not touch DI.

### Async

```csharp
string hash = await hasher.HashAsync(password);
var result = await hasher.VerifyAsync(password, storedHash, cancellationToken);
```

## Hash format

```
$pbkdf2-<algorithm>$v=1$i=<iterations>,l=<hashLength>$<base64_salt>$<base64_hash>
```

Example:

```
$pbkdf2-sha256$v=1$i=600000,l=32$c2FsdHNhbHRzYWx0c2E=$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE=
```

Verify parses algorithm, iteration count, and length directly from the hash,
so changing PasswordHasherOptions does not break existing hashes.

## Security

- Random salt generated with RandomNumberGenerator.GetBytes.
- Constant-time comparison via CryptographicOperations.FixedTimeEquals.
- Timing-safe fake verification via IMigratingPasswordHasher.FakeVerify.
- OWASP 2024 defaults: SHA256 with 600,000 iterations.
- Rehash support — increase parameters over time without breaking users.

### Recommended OWASP 2024 iteration counts

| Algorithm | Iterations |
|-----------|------------|
| SHA1      | 1,300,000  |
| SHA256    | 600,000    |
| SHA384    | 300,000    |
| SHA512    | 210,000    |

### Avoiding user enumeration

```csharp
public async Task<bool> LoginAsync(string email, string password)
{
var user = await _users.FindByEmailAsync(email);

    if (user is null)
    {
        // Burn the same time as a real verification, always returns false.
        _hasher.FakeVerify(password);
        return false;
    }

    var result = _hasher.Verify(password, user.PasswordHash);

    if (result == PasswordVerificationResult.SuccessRehashNeeded)
    {
        user.PasswordHash = _hasher.Hash(password);
        await _users.UpdateAsync(user);
    }

    return result != PasswordVerificationResult.Failed;
}
```

## Migration from a custom format

If you already store (hash, salt) columns, do a one-time migration:

```csharp
string oldHash = row.PasswordHash;
byte[] oldSalt = Convert.FromBase64String(row.PasswordSalt);

// On successful login, rehash with the new format and update the row.
if (VerifyLegacy(password, oldHash, oldSalt))
{
    row.PasswordHash = hasher.Hash(password);
    row.PasswordSalt = null; // column no longer needed
}
```

## Implemented interfaces

PasswordHasher.PBKDF2.PasswordHasher implements
PasswordHasher.Abstractions.IMigratingPasswordHasher, which extends
IPasswordHasher. A single DI registration serves both interfaces.

## License

MIT