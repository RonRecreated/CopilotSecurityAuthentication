# Simple secure login test project

This is a small ASP.NET Core Razor Pages app using .NET 10 and MySQL.
Razor Pages combines ordinary HTML with C# and automatically encodes displayed values.
No JavaScript or frontend framework is needed.

## What changed and why

- Your HTML collected a username and email, but had no password or working `/submit` handler.
  The working login form is now `Pages/Login.cshtml`; email is not needed for this username login.
  `webform.html` points you to the running application.
- Your SQL used MySQL's `AUTO_INCREMENT`, but your C# used SQL Server's `SqlConnection`.
  Both now use MySQL, through MySqlConnector.
- The original C# had instance methods inside a static class and undefined `script`/`iframe` variables.
  Validation and database access now have separate, small classes.
- The original tests referred to nonexistent `SanitizeInput` and `AuthenticationService` methods.
  The replacement tests exercise the actual validator and password handling.

## How the protections work

1. **Input validation:** `InputValidator.cs` accepts usernames of 3-30 ASCII letters,
   digits, underscores or hyphens. Passwords must be 15-128 characters. Browser checks
   help the user; C# checks enforce the rules even if browser checks are bypassed.
   Usernames are case-sensitive in this example. Passwords are never trimmed or altered.
2. **SQL injection:** `UserRepository.cs` uses SQL parameters for all user values.
   Do not concatenate input into SQL. Removing quotes or blocking words such as `DROP`
   is not a replacement for parameters.
3. **XSS:** Razor encodes values such as `@User.Identity?.Name` when writing HTML.
   Keep user data in ordinary text or quoted HTML attributes. Do not use `Html.Raw`,
   JavaScript `innerHTML`, or insert user input into script/style blocks. Looking for
   `<script>` misses many attacks. A restrictive Content Security Policy adds protection.
4. **Passwords:** ASP.NET's `PasswordHasher` creates a salted hash. Only that hash is
   stored in MySQL. Login fetches the hash and verifies it in C#; SQL never compares passwords.
5. **Sessions:** ASP.NET issues a protected, HttpOnly, HTTPS-only cookie after successful
   login. The account page requires authentication. Logout uses a protected POST form.
6. **Forms and guessing:** Razor POST forms use anti-forgery tokens (CSRF protection).
   Login failures use the same message. A simple global limit permits 10 login POSTs per
   minute per running app, then returns HTTP 429. GET requests do not consume that limit.

## Run it

You need the .NET 10 SDK and a running MySQL server.

1. In MySQL Workbench or the MySQL client, create a **new test database**, select it,
   and run `database.sql`:

   ```sql
   CREATE DATABASE SecureLoginTest;
   USE SecureLoginTest;
   -- Run the contents of database.sql here.
   ```

   The script creates a fresh Users table. If you already have one, use a separate test
   database rather than dropping your data. Existing rows have no password hashes and
   cannot log in without being migrated or having passwords set.

2. In PowerShell in this project folder, set the connection string for this terminal.
   Replace the example credentials with your own. Use a database account scoped to this
   test database, with SELECT and INSERT permissions, rather than the MySQL root account.

   ```powershell
   $env:ConnectionStrings__Users = 'Server=localhost;Database=SecureLoginTest;User ID=YOUR_DB_USER;Password=YOUR_DB_PASSWORD'
   dotnet restore SecureLogin.csproj
   dotnet dev-certs https --trust
   ```

   Keep actual credentials out of source files. For a remote database, configure
   certificate validation with `SslMode=VerifyFull` and your server's trusted CA.

3. Create a test login. The command asks for a username and a hidden password; use
   a passphrase of at least 15 characters. Choose a username that does not already exist.

   ```powershell
   dotnet run --project SecureLogin.csproj -- --create-user
   ```

4. Start the website:

   ```powershell
   dotnet run --project SecureLogin.csproj -- --urls https://localhost:7001
   ```

   Open [the login page](https://localhost:7001/Login). Opening the `.cshtml` or `.html`
   file directly does not run the login server. Stop it with Ctrl+C.

## Check it

```powershell
dotnet build SecureLogin.csproj
dotnet test Tests/SecureLogin.Tests.csproj
```

While the website is running, `pwsh -File Tests/SmokeTest.ps1` checks redirects,
anti-forgery enforcement, rejected attack usernames, reflected HTML, and rate limiting
over local HTTPS. This test consumes the login attempt quota; wait a minute afterward.

The automated tests check username rules and password length, exact verification,
and random salts. They do not require MySQL and do not prove SQL injection or XSS
protection by themselves. Parameters and output encoding are separate defenses.

After configuring MySQL, check the full flow: a correct login reaches the account page;
a wrong password fails; logout removes access; visiting `/` without a login redirects
to `/Login`. Try `admin' OR 1=1 --` and `<img src=x onerror=alert(1)>` as usernames:
they should fail and any reflected text must remain encoded. A POST without a valid
anti-forgery token must return HTTP 400.

This is a learning example. Its global in-memory rate limit resets on restart and
is shared by all users. A public multi-user app needs a more complete account system,
such as ASP.NET Core Identity, including recovery and abuse controls.

## References

- [Microsoft: prevent XSS](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0)
- [MySqlConnector: parameterized commands](https://mysqlconnector.net/tutorials/basic-api/)
- [Microsoft: password hashing](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing?view=aspnetcore-10.0)
- [Microsoft: cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-10.0)
