namespace PasswordHasher.Abstractions;

/// <summary>
/// Extended password hasher contract with migration and timing-safety helpers.
/// </summary>
public interface IMigratingPasswordHasher : IPasswordHasher
{
    /// <summary>
    /// Performs a fake verification to mitigate timing attacks and user enumeration.
    /// Consumes the same amount of time as <see cref="IPasswordHasher.Verify"/>
    /// but always returns <see cref="PasswordVerificationResult.Failed"/>.
    /// </summary>
    /// <param name="password">The plaintext password (unused, but required to align timing).</param>
    bool FakeVerify(string password);

    /// <summary>
    /// Determines whether a hash needs to be rehashed.
    /// </summary>
    /// <param name="hash">The stored hash.</param>
    /// <returns><c>true</c> if the hash should be rehashed; otherwise <c>false</c>.</returns>
    bool NeedsRehash(string hash);

    /// <summary>Asynchronous version of <see cref="FakeVerify"/>.</summary>
    Task<bool> FakeVerifyAsync(string password, CancellationToken cancellationToken = default);
}