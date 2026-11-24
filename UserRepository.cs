using MySqlConnector;

namespace SecureLogin;

public sealed record LoginUser(int Id, string Username, string PasswordHash);

public sealed class UserRepository(IConfiguration configuration)
{
    private MySqlConnection CreateConnection() => new(
        configuration.GetConnectionString("Users") ??
        throw new InvalidOperationException("Set ConnectionStrings__Users first. See README.md."));

    public async Task<LoginUser?> FindAsync(string username)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync();
        // SQL stays fixed. The parameter is sent as DATA, never executable SQL.
        using var command = new MySqlCommand(
            "SELECT UserID, Username, PasswordHash FROM Users WHERE Username = @username LIMIT 1",
            connection);
        command.Parameters.Add("@username", MySqlDbType.VarChar, 30).Value = username;
        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync()
            ? new LoginUser(reader.GetInt32(0), reader.GetString(1), reader.GetString(2))
            : null;
    }

    public async Task CreateAsync(string username, string passwordHash)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync();
        using var command = new MySqlCommand(
            "INSERT INTO Users (Username, PasswordHash) VALUES (@username, @hash)", connection);
        command.Parameters.Add("@username", MySqlDbType.VarChar, 30).Value = username;
        command.Parameters.Add("@hash", MySqlDbType.VarChar, 255).Value = passwordHash;
        await command.ExecuteNonQueryAsync();
    }
}
