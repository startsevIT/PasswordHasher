namespace PasswordHasher.Abstractions;

/// <summary>
/// Result of a password verification.
/// </summary>
public enum PasswordVerificationResult
{
    /// <summary>The password does not match the hash.</summary>
    Failed = 0,

    /// <summary>The password matches the hash.</summary>
    Success = 1,

    /// <summary>
    /// The password matches, but the hash was created with outdated parameters
    /// and should be rehashed and updated.
    /// </summary>
    SuccessRehashNeeded = 2
}