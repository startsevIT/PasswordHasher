using Microsoft.Extensions.Options;
using PasswordHasher.Abstractions;
using PasswordHasher.PBKDF2;

namespace PasswordHasher.Tests;

[TestFixture]
public sealed class PasswordHasherTests
{
    private static PBKDF2.PasswordHasher CreateHasher(Action<PasswordHasherOptions>? configure = null)
    {
        var options = new PasswordHasherOptions();
        configure?.Invoke(options);
        return new PBKDF2.PasswordHasher(Options.Create(options));
    }

    [Test]
    public void Hash_ReturnsSelfContainedString()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("correct horse battery staple");

        Assert.That(hash, Does.Match(@"^\$pbkdf2-sha256\$v=1\$i=600000,l=32\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"));
    }

    [Test]
    public void Hash_ReturnsDifferentHashesForSamePassword()
    {
        var hasher = CreateHasher();
        var hash1 = hasher.Hash("secret");
        var hash2 = hasher.Hash("secret");

        Assert.That(hash1, Is.Not.EqualTo(hash2));
    }

    [Test]
    public void Verify_ReturnsSuccess_ForCorrectPassword()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("secret");

        Assert.That(hasher.Verify("secret", hash), Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public void Verify_ReturnsFailed_ForWrongPassword()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("secret");

        Assert.That(hasher.Verify("wrong", hash), Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void Verify_ReturnsFailed_ForMalformedHash()
    {
        var hasher = CreateHasher();

        Assert.That(hasher.Verify("secret", "not-a-hash"), Is.EqualTo(PasswordVerificationResult.Failed));
        Assert.That(hasher.Verify("secret", ""), Is.EqualTo(PasswordVerificationResult.Failed));
        Assert.That(hasher.Verify("secret", "$pbkdf2-sha256$v=1$i=600000,l=32$bad$bad"), Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public void Verify_Throws_ForNullPassword()
    {
        var hasher = CreateHasher();

        Assert.Throws<ArgumentNullException>(() => hasher.Verify(null!, "hash"));
    }

    [Test]
    public void Verify_ReturnsSuccessRehashNeeded_WhenIterationsAreLower()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("secret");

        var upgraded = CreateHasher(o => o.IterationCount = 1_000_000);
        Assert.That(upgraded.Verify("secret", hash), Is.EqualTo(PasswordVerificationResult.SuccessRehashNeeded));
    }

    [Test]
    public void Verify_ReturnsSuccessRehashNeeded_WhenAlgorithmDiffers()
    {
        var hasher = CreateHasher(o => o.Algorithm = "SHA256");
        var hash = hasher.Hash("secret");

        var upgraded = CreateHasher(o => o.Algorithm = "SHA512");
        Assert.That(upgraded.Verify("secret", hash), Is.EqualTo(PasswordVerificationResult.SuccessRehashNeeded));
    }

    [Test]
    public void NeedsRehash_ReturnsFalse_ForCurrentHash()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("secret");

        Assert.That(hasher.NeedsRehash(hash), Is.False);
    }

    [Test]
    public void NeedsRehash_ReturnsTrue_ForEmptyHash()
    {
        var hasher = CreateHasher();
        Assert.That(hasher.NeedsRehash(""), Is.True);
    }

    [Test]
    public void NeedsRehash_ReturnsTrue_ForOutdatedIterations()
    {
        var oldHasher = CreateHasher(o => o.IterationCount = 100_000);
        var oldHash = oldHasher.Hash("secret");

        var newHasher = CreateHasher(o => o.IterationCount = 600_000);
        Assert.That(newHasher.NeedsRehash(oldHash), Is.True);
    }

    [Test]
    public void FakeVerify_AlwaysReturnsFalse()
    {
        var hasher = CreateHasher();

        Assert.That(hasher.FakeVerify("anything"), Is.False);
        Assert.That(hasher.FakeVerify(""), Is.False);
    }

    [Test]
    public async Task HashAsync_ReturnsSameResultAsHash()
    {
        var hasher = CreateHasher();
        var hash = await hasher.HashAsync("secret");

        Assert.That(hasher.Verify("secret", hash), Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task VerifyAsync_WorksWithCorrectPassword()
    {
        var hasher = CreateHasher();
        var hash = hasher.Hash("secret");

        Assert.That(await hasher.VerifyAsync("secret", hash), Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task FakeVerifyAsync_AlwaysReturnsFalse()
    {
        var hasher = CreateHasher();
        Assert.That(await hasher.FakeVerifyAsync("anything"), Is.False);
    }

    [TestCase("SHA1")]
    [TestCase("SHA256")]
    [TestCase("SHA384")]
    [TestCase("SHA512")]
    public void Hash_WorksWithAllSupportedAlgorithms(string algorithm)
    {
        var hasher = CreateHasher(o => o.Algorithm = algorithm);
        var hash = hasher.Hash("secret");

        Assert.That(hasher.Verify("secret", hash), Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public void Constructor_Throws_ForUnsupportedAlgorithm()
    {
        Assert.Throws<ArgumentException>(() => CreateHasher(o => o.Algorithm = "MD5"));
    }

    [Test]
    public void Constructor_Throws_ForLowIterations()
    {
        Assert.Throws<ArgumentException>(() => CreateHasher(o => o.IterationCount = 10_000));
    }

    [Test]
    public void Constructor_Throws_ForLowSaltSize()
    {
        Assert.Throws<ArgumentException>(() => CreateHasher(o => o.SaltSize = 4));
    }

    [Test]
    public void Constructor_Throws_ForLowHashSize()
    {
        Assert.Throws<ArgumentException>(() => CreateHasher(o => o.HashSize = 8));
    }
}