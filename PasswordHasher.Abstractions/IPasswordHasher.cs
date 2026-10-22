namespace PasswordHasher.Abstractions;

/// <summary>
/// Hashes and verifies passwords using a self-contained hash format.
/// </summary>
/// <remarks>
/// The hash string contains the algorithm, parameters, salt, and hash,
/// so it can be verified even after options change.
/// </remarks>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a password and returns a self-contained string.
    /// </summary>
    /// <param name="password">The plaintext password.</param>
    /// <returns>A hash string suitable for storage.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <c>null</c>.</exception>
    string Hash(string password);

    /// <summary>
    /// Verifies a password against a stored hash.
    /// </summary>
    /// <param name="password">The plaintext password.</param>
    /// <param name="hash">The stored hash (result of <see cref="Hash"/>).</param>
    /// <returns>One of <see cref="PasswordVerificationResult"/> values.</returns>
    PasswordVerificationResult Verify(string password, string hash);

    /// <summary>Asynchronous version of <see cref="Hash"/>.</summary>
    Task<string> HashAsync(string password, CancellationToken cancellationToken = default);

    /// <summary>Asynchronous version of <see cref="Verify"/>.</summary>
    Task<PasswordVerificationResult> VerifyAsync(
        string password,
        string hash,
        CancellationToken cancellationToken = default);
}