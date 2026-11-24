using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using System.Threading.RateLimiting;
using SecureLogin;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddSingleton<PasswordHasher<string>>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login";
        options.Cookie.Name = "__Host-SecureLogin";
        options.Cookie.HttpOnly = true; // JavaScript cannot read the login cookie.
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only.
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        options.SlidingExpiration = false;
    });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery(options => options.Cookie.SecurePolicy = CookieSecurePolicy.Always);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    // Simple process-wide limit for this test app: 10 login attempts per minute.
    options.AddPolicy("login", context => HttpMethods.IsPost(context.Request.Method)
        ? RateLimitPartition.GetFixedWindowLimiter("login", _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0
        })
        : RateLimitPartition.GetNoLimiter<string>("login-page"));
});

var app = builder.Build();

// Create a test account in the terminal; this avoids a public registration page.
if (args.Contains("--create-user"))
{
    Console.Write("Username: ");
    var username = Console.ReadLine();
    Console.Write("Password (hidden): ");
    var password = "";
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0) password = password[..^1];
        }
        else if (!char.IsControl(key.KeyChar) && password.Length < 129)
            password += key.KeyChar;
    }
    Console.WriteLine();
    if (!InputValidator.IsValidUsername(username) || !InputValidator.IsValidPassword(password))
        throw new ArgumentException("Use a 3-30 character username and a 15-128 character password.");
    using var scope = app.Services.CreateScope();
    var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher<string>>();
    // PasswordHasher generates a random salt and includes it inside the hash.
    await scope.ServiceProvider.GetRequiredService<UserRepository>()
        .CreateAsync(username!, hasher.HashPassword(username!, password));
    Console.WriteLine("Test user created.");
    return;
}

// Do not expose SQL errors or stack traces to the browser.
app.UseExceptionHandler(error => error.Run(async context =>
{
    context.Response.StatusCode = 500;
    await context.Response.WriteAsync("Something went wrong. Please try again later.");
}));
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    // Extra browser protection. Output encoding is still the primary XSS defense.
    context.Response.Headers.ContentSecurityPolicy =
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.CacheControl = "no-store";
    await next();
});
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapRazorPages();
app.Run();
