# PasswordHasher.Abstractions

Core interfaces and result types for the PasswordHasher library.

This package has no dependencies and is safe to reference from domain
and business-logic projects that should not depend on a specific hashing
implementation.

## Install

dotnet add package PasswordHasher.Abstractions

## What's inside

| Type                       | Description                                         |
|----------------------------|-----------------------------------------------------|
| IPasswordHasher            | Minimal contract: Hash, Verify, and async versions. |
| IMigratingPasswordHasher   | Extended contract: adds NeedsRehash and FakeVerify. |
| PasswordVerificationResult | Result of a password verification.                  |

## Interfaces

```csharp
public interface IPasswordHasher
{
  string Hash(string password);
  PasswordVerificationResult Verify(string password, string hash);
  Task<string> HashAsync(string password, CancellationToken cancellationToken = default);
  Task<PasswordVerificationResult> VerifyAsync(string password, string hash, CancellationToken cancellationToken =
  default);
}

public interface IMigratingPasswordHasher : IPasswordHasher
{
  bool FakeVerify(string password);
  bool NeedsRehash(string hash);
  Task<bool> FakeVerifyAsync(string password, CancellationToken cancellationToken = default);
}
```

Reference IPasswordHasher in your services. Use IMigratingPasswordHasher
only if you need rehashing or timing-safe fake verification.

## PasswordVerificationResult

```csharp
public enum PasswordVerificationResult
{
  Failed = 0,
  Success = 1,
  SuccessRehashNeeded = 2
}
```

- Failed — the password does not match.
- Success — the password matches and the hash parameters are up to date.
- SuccessRehashNeeded — the password matches, but the hash should be rehashed
  (for example, after increasing IterationCount).

## Usage

```csharp
public sealed class AuthService(IPasswordHasher hasher)
{
public string Register(string password) => hasher.Hash(password);

    public bool Login(string password, string storedHash)
    {
        var result = hasher.Verify(password, storedHash);

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            // The password is correct, but the hash is outdated.
            // Rehash and persist the new value.
        }

        return result != PasswordVerificationResult.Failed;
    }
}
```


## Implementations

See PasswordHasher.PBKDF2 for a production-ready PBKDF2 implementation.

## License

MIT