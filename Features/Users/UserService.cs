using System.Security.Cryptography;
using System.Text;

namespace Notes_App.Features.Users;

public class UserService
{
    private const int PasswordIterations = 600_000;
    private const int PasswordHashSize = 32;

    private readonly object _sync = new();
    private readonly List<User> _users;
    private readonly byte[] _dummyPasswordSalt = RandomNumberGenerator.GetBytes(16);
    private readonly byte[] _dummyPasswordHash;
    private int _nextId;

    public UserService(IConfiguration configuration)
    {
        _users = configuration.GetSection("DemoUsers").GetChildren()
            .Select(section => new User(
                int.Parse(section["Id"] ?? throw new InvalidOperationException("DemoUsers.Id is required.")),
                section["Username"] ?? throw new InvalidOperationException("DemoUsers.Username is required."),
                Convert.FromBase64String(section["PasswordSalt"] ?? throw new InvalidOperationException("DemoUsers.PasswordSalt is required.")),
                Convert.FromBase64String(section["PasswordHash"] ?? throw new InvalidOperationException("DemoUsers.PasswordHash is required."))))
            .ToList();

        if (_users.Count == 0)
            throw new InvalidOperationException("At least one DemoUsers entry is required.");
        if (_users.Any(user => user.Id <= 0 || string.IsNullOrWhiteSpace(user.Username) || user.PasswordSalt.Length != 16 || user.PasswordHash.Length != PasswordHashSize))
            throw new InvalidOperationException("DemoUsers entries have an invalid ID, username, salt, or password hash.");
        if (_users.Select(user => user.Id).Distinct().Count() != _users.Count ||
            _users.Select(user => user.Username).Distinct(StringComparer.OrdinalIgnoreCase).Count() != _users.Count)
            throw new InvalidOperationException("DemoUsers IDs and usernames must be unique.");

        _nextId = _users.Max(user => user.Id) + 1;
        _dummyPasswordHash = HashPassword("invalid-password-placeholder", _dummyPasswordSalt);
    }

    public User Create(UserRequest request)
    {
        var username = ValidateUsername(request.Username);
        var password = ValidatePassword(request.Password);

        lock (_sync)
        {
            EnsureUsernameAvailable(username);
            var salt = RandomNumberGenerator.GetBytes(16);
            var user = new User(_nextId++, username, salt, HashPassword(password, salt));
            _users.Add(user);
            return user;
        }
    }

    public User? GetById(int id)
    {
        lock (_sync)
            return _users.FirstOrDefault(user => user.Id == id);
    }

    public User? GetByUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return null;

        lock (_sync)
            return _users.FirstOrDefault(user => string.Equals(user.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    public User? Authenticate(string? username, string? password)
    {
        User? user;
        byte[] salt;
        byte[] expectedHash;

        lock (_sync)
        {
            user = string.IsNullOrWhiteSpace(username)
                ? null
                : _users.FirstOrDefault(candidate => string.Equals(candidate.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));
            salt = (user?.PasswordSalt ?? _dummyPasswordSalt).ToArray();
            expectedHash = (user?.PasswordHash ?? _dummyPasswordHash).ToArray();
        }

        var actualHash = HashPassword(password ?? string.Empty, salt);
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash) ? user : null;
    }

    public User? Update(int id, UserRequest request)
    {
        var username = ValidateUsername(request.Username);
        var password = string.IsNullOrWhiteSpace(request.Password) ? null : ValidatePassword(request.Password);

        lock (_sync)
        {
            var index = _users.FindIndex(user => user.Id == id);
            if (index < 0)
                return null;

            EnsureUsernameAvailable(username, id);
            var current = _users[index];
            var salt = password is null ? current.PasswordSalt : RandomNumberGenerator.GetBytes(16);
            var hash = password is null ? current.PasswordHash : HashPassword(password, salt);
            var updated = new User(id, username, salt, hash);
            _users[index] = updated;
            return updated;
        }
    }

    public bool Delete(int id)
    {
        lock (_sync)
        {
            var user = _users.FirstOrDefault(candidate => candidate.Id == id);
            return user is not null && _users.Remove(user);
        }
    }

    public List<User> GetAll()
    {
        lock (_sync)
            return [.. _users];
    }

    private void EnsureUsernameAvailable(string username, int? exceptId = null)
    {
        if (_users.Any(user => user.Id != exceptId && string.Equals(user.Username, username, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("A user with this username already exists.");
    }

    private static string ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty.", nameof(username));

        return username.Trim();
    }

    private static string ValidatePassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            throw new ArgumentException("Password must contain at least 8 characters.", nameof(password));

        return password;
    }

    private static byte[] HashPassword(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, PasswordIterations, HashAlgorithmName.SHA256, PasswordHashSize);
}

public sealed record UserRequest(string? Username, string? Password);
