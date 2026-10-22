using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using PasswordHasher.Abstractions;

namespace PasswordHasher.PBKDF2;

/// <summary>
/// PBKDF2 implementation of <see cref="IPasswordHasher"/> and <see cref="IMigratingPasswordHasher"/>.
/// </summary>
public sealed class PasswordHasher : IMigratingPasswordHasher
{
    private const string FormatPrefix = "$pbkdf2-";
    private const int FormatVersion = 1;

    private static readonly HashSet<string> SupportedAlgorithms = new(StringComparer.Ordinal)
    {
        "SHA1", "SHA256", "SHA384", "SHA512"
    };

    private static readonly byte[] DummyPasswordBytes =
        "dummy-password-for-timing-protection"u8.ToArray();

    private readonly PasswordHasherOptions _options;
    private readonly HashAlgorithmName _hashAlgorithm;

    // Computed once on first FakeVerify. Cached to avoid regenerating salt on every call.
    private readonly Lazy<byte[]> _dummyHash;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHasher"/> class.
    /// </summary>
    /// <param name="options">The hasher options.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">The options contain invalid values.</exception>
    public PasswordHasher(IOptions<PasswordHasherOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;

        ValidateOptions(_options);

        _hashAlgorithm = new HashAlgorithmName(_options.Algorithm);

        _dummyHash = new Lazy<byte[]>(() =>
            Rfc2898DeriveBytes.Pbkdf2(
                DummyPasswordBytes,
                RandomNumberGenerator.GetBytes(_options.SaltSize),
                _options.IterationCount,
                _hashAlgorithm,
                _options.HashSize));
    }

    /// <inheritdoc />
    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var saltBytes = RandomNumberGenerator.GetBytes(_options.SaltSize);
        var hashBytes = ComputeHash(password, saltBytes);

        return Encode(_options.Algorithm, _options.IterationCount, _options.HashSize, saltBytes, hashBytes);
    }

    /// <inheritdoc />
    public PasswordVerificationResult Verify(string password, string hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (string.IsNullOrEmpty(hash))
            return PasswordVerificationResult.Failed;

        if (!TryDecode(hash, out var algorithm, out var iterations, out var length, out var saltBytes, out var expectedHash))
            return PasswordVerificationResult.Failed;

        var computed = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            saltBytes,
            iterations,
            new HashAlgorithmName(algorithm),
            length);

        if (computed.Length != expectedHash.Length
            || !CryptographicOperations.FixedTimeEquals(computed, expectedHash))
        {
            return PasswordVerificationResult.Failed;
        }

        var needsRehash =
            !string.Equals(algorithm, _options.Algorithm, StringComparison.Ordinal)
            || iterations < _options.IterationCount
            || length < _options.HashSize;

        return needsRehash
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
    }

    /// <inheritdoc />
    public bool FakeVerify(string password)
    {
        _ = password;
        _ = _dummyHash.Value; // burn time as a real verification would
        return false;
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hash)
    {
        if (string.IsNullOrEmpty(hash))
            return true;

        if (!TryDecode(hash, out var algorithm, out var iterations, out var length, out _, out _))
            return true;

        return !string.Equals(algorithm, _options.Algorithm, StringComparison.Ordinal)
            || iterations < _options.IterationCount
            || length < _options.HashSize;
    }

    /// <inheritdoc />
    public Task<string> HashAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Task.Run(() => Hash(password), cancellationToken);
    }

    /// <inheritdoc />
    public Task<PasswordVerificationResult> VerifyAsync(
        string password,
        string hash,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return Task.Run(() => Verify(password, hash), cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> FakeVerifyAsync(string password, CancellationToken cancellationToken = default)
    {
        _ = password;
        return Task.Run(() => FakeVerify(password), cancellationToken);
    }

    // ---------- Internal ----------

    private byte[] ComputeHash(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            _options.IterationCount,
            _hashAlgorithm,
            _options.HashSize);

    private static string Encode(
        string algorithm,
        int iterations,
        int length,
        byte[] salt,
        byte[] hash)
    {
        // Format: $pbkdf2-sha256$v=1$i=600000,l=32$<base64_salt>$<base64_hash>
        var sb = new StringBuilder(64 + salt.Length + hash.Length);
        sb.Append(FormatPrefix);
        sb.Append(algorithm.ToLowerInvariant());
        sb.Append("$v=").Append(FormatVersion.ToString(CultureInfo.InvariantCulture));
        sb.Append("$i=").Append(iterations.ToString(CultureInfo.InvariantCulture));
        sb.Append(",l=").Append(length.ToString(CultureInfo.InvariantCulture));
        sb.Append('$').Append(Convert.ToBase64String(salt));
        sb.Append('$').Append(Convert.ToBase64String(hash));
        return sb.ToString();
    }

    private static bool TryDecode(
        string encoded,
        out string algorithm,
        out int iterations,
        out int length,
        out byte[] salt,
        out byte[] hash)
    {
        algorithm = string.Empty;
        iterations = 0;
        length = 0;
        salt = Array.Empty<byte>();
        hash = Array.Empty<byte>();

        var parts = encoded.Split('$');
        // Expected: ['', 'pbkdf2-sha256', 'v=1', 'i=600000,l=32', '<salt>', '<hash>']
        if (parts.Length != 6 || parts[0].Length != 0)
            return false;

        if (!parts[1].StartsWith("pbkdf2-", StringComparison.Ordinal))
            return false;

        algorithm = parts[1]["pbkdf2-".Length..].ToUpperInvariant();
        if (!SupportedAlgorithms.Contains(algorithm))
            return false;

        if (!parts[2].StartsWith("v=", StringComparison.Ordinal))
            return false;
        if (!int.TryParse(parts[2][2..], NumberStyles.None, CultureInfo.InvariantCulture, out var version)
            || version != FormatVersion)
            return false;

        var paramsPart = parts[3].Split(',');
        if (paramsPart.Length != 2)
            return false;

        if (!paramsPart[0].StartsWith("i=", StringComparison.Ordinal)
            || !int.TryParse(paramsPart[0][2..], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
            || iterations <= 0)
            return false;

        if (!paramsPart[1].StartsWith("l=", StringComparison.Ordinal)
            || !int.TryParse(paramsPart[1][2..], NumberStyles.None, CultureInfo.InvariantCulture, out length)
            || length <= 0)
            return false;

        try
        {
            salt = Convert.FromBase64String(parts[4]);
            hash = Convert.FromBase64String(parts[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        return true;
    }

    private static void ValidateOptions(PasswordHasherOptions options)
    {
        if (!SupportedAlgorithms.Contains(options.Algorithm))
            throw new ArgumentException(
                $"Unsupported hash algorithm: {options.Algorithm}. " +
                $"Supported: {string.Join(", ", SupportedAlgorithms)}.",
                nameof(options.Algorithm));

        if (options.SaltSize < 8)
            throw new ArgumentException("SaltSize must be at least 8 bytes.", nameof(options));

        if (options.HashSize < 16)
            throw new ArgumentException("HashSize must be at least 16 bytes.", nameof(options));

        if (options.IterationCount < 100_000)
            throw new ArgumentException(
                "IterationCount must be at least 100,000 for PBKDF2 to be considered secure.",
                nameof(options));
    }
}