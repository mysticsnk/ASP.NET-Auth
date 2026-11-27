using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Notes_App.Features.JwtTokens;
using Notes_App.Features.Users;

namespace Notes_App.Features.Authorization;

public class AuthorizationService
{
    public ConcurrentDictionary<string, RefreshSession> RefreshSessions = new();
    public IResult Refresh(RefreshRequest? request)
    {
        var userService = AppState.App.Services.GetRequiredService <UserService>();
        
        if (string.IsNullOrWhiteSpace(request?.RefreshToken))
            return Results.BadRequest(new { error = "RefreshToken is required." });

        var tokenHash = HashRefreshToken(request.RefreshToken);
        if (!RefreshSessions.TryRemove(tokenHash, out var session) || session.ExpiresAt <= DateTimeOffset.UtcNow)
            return Results.Unauthorized();

        var user = userService.GetById(session.UserId);
        return user is null ? Results.Unauthorized() : Results.Ok(CreateTokenPair(user));
    }

    public TokenPair CreateTokenPair(User user)
    {
        var tokenService = AppState.App.Services.GetRequiredService<JwtTokenService>();
        
        var now = DateTimeOffset.UtcNow;
        var accessExpiresAt = now.AddMinutes(2);
        var accessToken = tokenService.Create(user.Id, user.Username, AppState.Issuer, AppState.SigningKey, now, accessExpiresAt);

        foreach (var entry in RefreshSessions)
        {
            if (entry.Value.ExpiresAt <= now)
                RefreshSessions.TryRemove(entry.Key, out _);
        }

        var refreshToken = tokenService.CreateOpaqueToken();
        RefreshSessions[HashRefreshToken(refreshToken)] = new RefreshSession(user.Id, now.AddDays(7));

        return new TokenPair(accessToken, refreshToken, "Bearer", 120, accessExpiresAt);
    }

    public string HashRefreshToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public  bool TryGetUserId(HttpContext context, out int userId) =>
        int.TryParse(context.User.FindFirstValue("userId"), NumberStyles.None, CultureInfo.InvariantCulture, out userId);
    
    public IResult Unauthorized(HttpContext context)
    {
        context.Response.Headers["WWW-Authenticate"] = "Bearer";
        return Results.Unauthorized();
    }
}