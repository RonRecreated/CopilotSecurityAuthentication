using Microsoft.AspNetCore.Identity;
using SecureLogin;
using Xunit;

public class TestInputValidation
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData("user name")]
    [InlineData("admin' OR 1=1 --")]
    [InlineData("'; DROP TABLE Users; --")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("admin\n")]
    [InlineData("usér")]
    public void RejectsInvalidUsernames(string? username) =>
        Assert.False(InputValidator.IsValidUsername(username));

    [Theory]
    [InlineData("abc")]
    [InlineData("Alice_123-test")]
    public void AcceptsValidUsernames(string username) =>
        Assert.True(InputValidator.IsValidUsername(username));

    [Fact]
    public void EnforcesUsernameLength()
    {
        Assert.True(InputValidator.IsValidUsername(new string('a', 30)));
        Assert.False(InputValidator.IsValidUsername(new string('a', 31)));
    }

    [Fact]
    public void EnforcesPasswordLength()
    {
        Assert.False(InputValidator.IsValidPassword(null));
        Assert.False(InputValidator.IsValidPassword(new string('x', 14)));
        Assert.True(InputValidator.IsValidPassword(new string('x', 15)));
        Assert.True(InputValidator.IsValidPassword(new string('x', 128)));
        Assert.False(InputValidator.IsValidPassword(new string('x', 129)));
    }

    [Fact]
    public void PasswordsKeepSymbolsAndWhitespace()
    {
        // These characters must not be removed. SQL parameters keep them safe.
        const string password = "  a 'quoted' <passphrase>!  ";
        Assert.True(InputValidator.IsValidPassword(password));
        var hasher = new PasswordHasher<string>();
        var hash = hasher.HashPassword("alice", password);
        Assert.NotEqual(password, hash);
        Assert.Equal(PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword("alice", hash, password));
        Assert.Equal(PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword("alice", hash, password.Trim()));
        Assert.Equal(PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword("alice", hash, "an incorrect password"));
        Assert.NotEqual(hash, hasher.HashPassword("alice", password));
    }
}
