using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Notes_App.Features.Notes;
using Notes_App.Features.Users;

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["Jwt:Issuer"];
var secret = builder.Configuration["Jwt:SecretKey"];

if (string.IsNullOrWhiteSpace(issuer))
    throw new InvalidOperationException("Configuration value 'Jwt:Issuer' is required.");
if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
    throw new InvalidOperationException("'Jwt:SecretKey' must contain at least 32 UTF-8 bytes.");

var signingKey = Encoding.UTF8.GetBytes(secret);
var refreshSessions = new ConcurrentDictionary<string, RefreshSession>();

builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<NoteService>();
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
var userService = app.Services.GetRequiredService<UserService>();
var noteService = app.Services.GetRequiredService<NoteService>();

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
app.MapGet("/notes/{id:int}", GetNote).RequireAuthorization();
app.MapPost("/notes", CreateNote).RequireAuthorization();
app.MapPut("/notes/{id:int}", UpdateNote).RequireAuthorization();
app.MapDelete("/notes/{id:int}", DeleteNote).RequireAuthorization();

app.Run();

IResult Login(LoginRequest? request)
{
    var user = userService.Authenticate(request?.Username, request?.Password);
    return user is null ? Results.Unauthorized() : Results.Ok(CreateTokenPair(user));
}

IResult Refresh(RefreshRequest? request)
{
    if (string.IsNullOrWhiteSpace(request?.RefreshToken))
        return Results.BadRequest(new { error = "RefreshToken is required." });

    var tokenHash = HashRefreshToken(request.RefreshToken);
    if (!refreshSessions.TryRemove(tokenHash, out var session) || session.ExpiresAt <= DateTimeOffset.UtcNow)
        return Results.Unauthorized();

    var user = userService.GetById(session.UserId);
    return user is null ? Results.Unauthorized() : Results.Ok(CreateTokenPair(user));
}

IResult ListNotes(HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);

    return Results.Ok(noteService.GetByOwnerId(userId));
}

IResult GetNote(int id, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);

    var note = noteService.GetById(id);
    return note is null || note.OwnerId != userId ? Results.NotFound() : Results.Ok(note);
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

    var note = noteService.Create(userId, request);
    return Results.Created($"/notes/{note.Id}", note);
}

IResult UpdateNote(int id, NoteRequest? request, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);
    if (request is null || string.IsNullOrWhiteSpace(request.Title))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["title"] = ["A non-empty title is required."]
        });

    var note = noteService.Update(id, userId, request);
    return note is null ? Results.NotFound() : Results.Ok(note);
}

IResult DeleteNote(int id, HttpContext context)
{
    if (!TryGetUserId(context, out var userId))
        return Unauthorized(context);

    return noteService.Delete(id, userId) ? Results.NoContent() : Results.NotFound();
}

TokenPair CreateTokenPair(User user)
{
    var now = DateTimeOffset.UtcNow;
    var accessExpiresAt = now.AddMinutes(2);
    var accessToken = JwtTokens.Create(user.Id, user.Username, issuer, signingKey, now, accessExpiresAt);

    foreach (var entry in refreshSessions)
    {
        if (entry.Value.ExpiresAt <= now)
            refreshSessions.TryRemove(entry.Key, out _);
    }

    var refreshToken = JwtTokens.CreateOpaqueToken();
    refreshSessions[HashRefreshToken(refreshToken)] = new RefreshSession(user.Id, now.AddDays(7));

    return new TokenPair(accessToken, refreshToken, "Bearer", 120, accessExpiresAt);
}

static string HashRefreshToken(string token) =>
    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

static bool TryGetUserId(HttpContext context, out int userId) =>
    int.TryParse(context.User.FindFirstValue("userId"), NumberStyles.None, CultureInfo.InvariantCulture, out userId);

static IResult Unauthorized(HttpContext context)
{
    context.Response.Headers["WWW-Authenticate"] = "Bearer";
    return Results.Unauthorized();
}

internal sealed record LoginRequest(string? Username, string? Password);
internal sealed record RefreshRequest(string? RefreshToken);
internal sealed record RefreshSession(int UserId, DateTimeOffset ExpiresAt);
internal sealed record TokenPair(string AccessToken, string RefreshToken, string TokenType, int ExpiresIn, DateTimeOffset AccessTokenExpiresAt);

internal static class JwtTokens
{
    public static string Create(int userId, string username, string issuer, byte[] signingKey, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var id = userId.ToString(CultureInfo.InvariantCulture);
        var token = new JwtSecurityToken(
            issuer: issuer,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, id),
                new Claim("userId", id),
                new Claim(JwtRegisteredClaimNames.Name, username),
                new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
            ],
            notBefore: issuedAt.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string CreateOpaqueToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
