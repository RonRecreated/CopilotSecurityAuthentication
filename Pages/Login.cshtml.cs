using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace SecureLogin.Pages;

[EnableRateLimiting("login")]
public sealed class LoginModel(UserRepository users, PasswordHasher<string> hasher) : PageModel
{
    [BindProperty] public string Username { get; set; } = "";
    [BindProperty] public string Password { get; set; } = "";

    // Unknown users still require a hash check, reducing username timing differences.
    private static readonly string DummyHash = new PasswordHasher<string>()
        .HashPassword("dummy", Guid.NewGuid().ToString());

    public void OnGet() { }

    // Razor Pages validates the anti-forgery token before running this handler.
    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid || !InputValidator.IsValidUsername(Username) ||
            !InputValidator.IsValidPassword(Password))
            return InvalidLogin();

        var user = await users.FindAsync(Username);
        var result = hasher.VerifyHashedPassword(Username, user?.PasswordHash ?? DummyHash, Password);
        if (user is null || result == PasswordVerificationResult.Failed)
            return InvalidLogin();

        // The framework protects this cookie; never put a password in it.
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username)
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
        return RedirectToPage("/Index");
    }

    private PageResult InvalidLogin()
    {
        // Same error for missing accounts and incorrect passwords.
        ModelState.Clear();
        ModelState.AddModelError("", "Invalid username or password.");
        Password = "";
        return Page();
    }
}
