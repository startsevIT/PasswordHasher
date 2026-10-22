using Microsoft.Extensions.Options;
using PasswordHasher.Abstractions;

namespace PasswordHasher.PBKDF2;

/// <summary>
/// Static facade over <see cref="PasswordHasher"/> with default options.
/// Intended for scripts, tests, and simple scenarios.
/// For DI and configuration use the instance-based <see cref="PasswordHasher"/>.
/// </summary>
public static class StaticPasswordHasher
{
    private static readonly PasswordHasher Default =
        new(Options.Create(new PasswordHasherOptions()));

    /// <inheritdoc cref="PasswordHasher.Hash"/>
    public static string Hash(string password) => Default.Hash(password);

    /// <inheritdoc cref="PasswordHasher.Verify"/>
    public static PasswordVerificationResult Verify(string password, string hash)
        => Default.Verify(password, hash);

    /// <inheritdoc cref="PasswordHasher.NeedsRehash"/>
    public static bool NeedsRehash(string hash) => Default.NeedsRehash(hash);

    /// <inheritdoc cref="PasswordHasher.FakeVerify"/>
    public static bool FakeVerify(string password) => Default.FakeVerify(password);

    /// <inheritdoc cref="PasswordHasher.HashAsync"/>
    public static Task<string> HashAsync(string password, CancellationToken cancellationToken = default)
        => Default.HashAsync(password, cancellationToken);

    /// <inheritdoc cref="PasswordHasher.VerifyAsync"/>
    public static Task<PasswordVerificationResult> VerifyAsync(
        string password,
        string hash,
        CancellationToken cancellationToken = default)
        => Default.VerifyAsync(password, hash, cancellationToken);

    /// <inheritdoc cref="PasswordHasher.FakeVerifyAsync"/>
    public static Task<bool> FakeVerifyAsync(string password, CancellationToken cancellationToken = default)
        => Default.FakeVerifyAsync(password, cancellationToken);
}