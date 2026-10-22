using System.ComponentModel.DataAnnotations;

namespace PasswordHasher.PBKDF2;

/// <summary>
/// Options for the PBKDF2 password hasher.
/// </summary>
public sealed class PasswordHasherOptions
{
    /// <summary>Default configuration section name.</summary>
    public const string SectionName = "PasswordHasher";

    /// <summary>
    /// Salt size in bytes. Minimum 8, recommended 16.
    /// </summary>
    [Range(8, 128)]
    public int SaltSize { get; set; } = 16;

    /// <summary>
    /// Hash size in bytes. Minimum 16, recommended 32.
    /// </summary>
    [Range(16, 128)]
    public int HashSize { get; set; } = 32;

    /// <summary>
    /// Number of PBKDF2 iterations. Minimum 100,000.
    /// OWASP 2024 recommendations: SHA1 — 1,300,000, SHA256 — 600,000, SHA512 — 210,000.
    /// </summary>
    [Range(100_000, int.MaxValue)]
    public int IterationCount { get; set; } = 600_000;

    /// <summary>
    /// PBKDF2 hash algorithm. Allowed values: SHA1, SHA256, SHA384, SHA512.
    /// </summary>
    [Required]
    public string Algorithm { get; set; } = "SHA256";
}