namespace SecureLogin;

public static class InputValidator
{
    // Username policy: 3-30 ASCII letters, numbers, underscores or hyphens.
    // Check on the server even when the HTML form also validates the input.
    public static bool IsValidUsername(string? value) =>
        value is { Length: >= 3 and <= 30 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    // Passwords may contain spaces, quotes and symbols. Never trim or sanitize them.
    // Limit their size to prevent oversized inputs from reaching the password hasher.
    public static bool IsValidPassword(string? value) =>
        value is { Length: >= 15 and <= 128 };
}
