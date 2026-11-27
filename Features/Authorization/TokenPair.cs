namespace Notes_App.Features.Authorization;

public record TokenPair(string AccessToken, string RefreshToken, string TokenType, int ExpiresIn, DateTimeOffset AccessTokenExpiresAt);