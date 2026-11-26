using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["Jwt:Issuer"];
var secret = builder.Configuration["Jwt:SecretKey"];
var configuredUsers = builder.Configuration.GetSection("DemoUsers").GetChildren()
    .Select(section => new ConfiguredUser(
        section["UserId"] ?? string.Empty,
        section["Username"] ?? string.Empty,
        section["PasswordSalt"] ?? string.Empty,
        section["PasswordHash"] ?? string.Empty))
    .ToArray();

if (string.IsNullOrWhiteSpace(issuer))
    throw new InvalidOperationException("Configuration value 'Jwt:Issuer' is required.");
if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
    throw new InvalidOperationException("'Jwt:SecretKey' must contain at least 32 UTF-8 bytes.");
if (configuredUsers.Length == 0 || configuredUsers.Any(user =>
        string.IsNullOrWhiteSpace(user.UserId) || string.IsNullOrWhiteSpace(user.Username) ||
        string.IsNullOrWhiteSpace(user.PasswordSalt) || string.IsNullOrWhiteSpace(user.PasswordHash)))
    throw new InvalidOperationException("At least one complete DemoUsers entry is required to seed the in-memory user store.");

var signingKey = Encoding.UTF8.GetBytes(secret);
var usersByUsername = configuredUsers.Select(user =>
    {
        var salt = Convert.FromBase64String(user.PasswordSalt);
        var passwordHash = Convert.FromBase64String(user.PasswordHash);
        if (salt.Length != 16 || passwordHash.Length != 32)
            throw new InvalidOperationException("DemoUsers password salts and hashes must decode to 16 and 32 bytes.");
        return new UserAccount(user.UserId, user.Username, salt, passwordHash);
    })
    .ToDictionary(user => user.Username, StringComparer.OrdinalIgnoreCase);
if (usersByUsername.Values.Select(user => user.UserId).Distinct(StringComparer.Ordinal).Count() != usersByUsername.Count)
    throw new InvalidOperationException("DemoUsers must have unique user IDs and usernames.");
var dummyPasswordSalt = RandomNumberGenerator.GetBytes(16);
var dummyPasswordHash = HashPassword("invalid-password-placeholder", dummyPasswordSalt);
var notes = new ConcurrentDictionary<Guid, Note>();
// Store only a hash of each opaque refresh token. A successful refresh removes
// the old hash before issuing its replacement, so the token can be used once.
var refreshSessions = new ConcurrentDictionary<string, RefreshSession>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKey),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = JwtRegisteredClaimNames.Name
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    message = "Private notes API",
    endpoints = new[] { "POST /login", "POST /refresh", "GET /notes", "GET /notes/{id}", "POST /notes", "PUT /notes/{id}", "DELETE /notes/{id}" }
}));

app.MapPost("/login", Login);
app.MapPost("/refresh", Refresh);
app.MapGet("/notes", ListNotes).RequireAuthorization();
app.MapGet("/notes/{id:guid}", GetNote).RequireAuthorization();
app.MapPost("/notes", CreateNote).RequireAuthorization();
app.MapPut("/notes/{id:guid}", UpdateNote).RequireAuthorization();
app.MapDelete("/notes/{id:guid}", DeleteNote).RequireAuthorization();

app.Run();

IResult Login(LoginRequest? request)
{
    var foundUser = usersByUsername.TryGetValue(request?.Username ?? string.Empty, out var user);
    var suppliedPassword = request?.Password ?? string.Empty;
    var suppliedPasswordHash = HashPassword(suppliedPassword, foundUser ? user!.PasswordSalt : dummyPasswordSalt);
    var expectedPasswordHash = foundUser ? user!.PasswordHash : dummyPasswordHash;
    var validPassword = CryptographicOperations.FixedTimeEquals(expectedPasswordHash, suppliedPasswordHash);

    if (!foundUser || !validPassword)
        return Results.Unauthorized();

    return Results.Ok(CreateTokenPair(user!.UserId, user.Username));
}

IResult Refresh(RefreshRequest? request)
{
    if (string.IsNullOrWhiteSpace(request?.RefreshToken))
        return Results.BadRequest(new { error = "RefreshToken is required." });

    var oldTokenHash = HashRefreshToken(request.RefreshToken);
    if (!refreshSessions.TryRemove(oldTokenHash, out var session) || session.ExpiresAt <= DateTimeOffset.UtcNow)
        return Results.Unauthorized();

    return Results.Ok(CreateTokenPair(session.UserId, session.Username));
}

IResult ListNotes(HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);

    var ownedNotes = notes.Values
        .Where(note => note.OwnerId == userId)
        .OrderByDescending(note => note.CreatedAt)
        .ToArray();

    return Results.Ok(ownedNotes);
}

IResult GetNote(Guid id, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);

    if (!notes.TryGetValue(id, out var note) || note.OwnerId != userId)
        return Results.NotFound();

    return Results.Ok(note);
}

IResult CreateNote(NoteRequest? request, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);
    if (request is null || string.IsNullOrWhiteSpace(request.Title))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["title"] = ["A non-empty title is required."]
        });

    var now = DateTimeOffset.UtcNow;
    var note = new Note(Guid.NewGuid(), userId, request.Title.Trim(), request.Content ?? string.Empty, now, now);
    notes[note.Id] = note;

    return Results.Created($"/notes/{note.Id}", note);
}

IResult UpdateNote(Guid id, NoteRequest? request, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);
    if (request is null || string.IsNullOrWhiteSpace(request.Title))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["title"] = ["A non-empty title is required."]
        });
    if (!notes.TryGetValue(id, out var current) || current.OwnerId != userId)
        return Results.NotFound();

    var updated = current with
    {
        Title = request.Title.Trim(),
        Content = request.Content ?? string.Empty,
        UpdatedAt = DateTimeOffset.UtcNow
    };

    if (!notes.TryUpdate(id, updated, current))
        return Results.Conflict(new { error = "The note changed during the update. Please retry." });

    return Results.Ok(updated);
}

IResult DeleteNote(Guid id, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);
    if (!notes.TryGetValue(id, out var note) || note.OwnerId != userId)
        return Results.NotFound();
    if (!notes.TryRemove(id, out _))
        return Results.NotFound();

    return Results.NoContent();
}

TokenPair CreateTokenPair(string userId, string username)
{
    var now = DateTimeOffset.UtcNow;
    var accessExpiresAt = now.AddMinutes(2);
    var accessToken = JwtTokens.Create(userId, username, issuer, signingKey, now, accessExpiresAt);

    // Expired entries are removed as users log in or rotate tokens.
    foreach (var entry in refreshSessions)
    {
        if (entry.Value.ExpiresAt <= now)
            refreshSessions.TryRemove(entry.Key, out _);
    }

    var refreshToken = JwtTokens.CreateOpaqueToken();
    refreshSessions[HashRefreshToken(refreshToken)] = new RefreshSession(userId, username, now.AddDays(7));

    return new TokenPair(accessToken, refreshToken, "Bearer", 120, accessExpiresAt);
}

static string HashRefreshToken(string token) =>
    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

static byte[] HashPassword(string password, byte[] salt) =>
    Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 600_000, HashAlgorithmName.SHA256, 32);

static bool TryGetUserId(HttpContext context, out string userId)
{
    userId = context.User.FindFirstValue("userId") ?? string.Empty;
    return !string.IsNullOrWhiteSpace(userId);
}

static IResult Unauthorized(HttpContext context)
{
    context.Response.Headers["WWW-Authenticate"] = "Bearer";
    return Results.Unauthorized();
}

internal sealed record LoginRequest(string? Username, string? Password);
internal sealed record RefreshRequest(string? RefreshToken);
internal sealed record NoteRequest(string? Title, string? Content);
internal sealed record Note(Guid Id, string OwnerId, string Title, string Content, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);
internal sealed record ConfiguredUser(string UserId, string Username, string PasswordSalt, string PasswordHash);
internal sealed record UserAccount(string UserId, string Username, byte[] PasswordSalt, byte[] PasswordHash);
internal sealed record RefreshSession(string UserId, string Username, DateTimeOffset ExpiresAt);
internal sealed record TokenPair(string AccessToken, string RefreshToken, string TokenType, int ExpiresIn, DateTimeOffset AccessTokenExpiresAt);

internal static class JwtTokens
{
    public static string Create(string userId, string username, string issuer, byte[] signingKey, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var token = new JwtSecurityToken(
            issuer: issuer,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim("userId", userId),
                new Claim(JwtRegisteredClaimNames.Name, username),
                new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
            ],
            notBefore: issuedAt.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string CreateOpaqueToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
