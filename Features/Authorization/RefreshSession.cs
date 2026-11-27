namespace Notes_App.Features.Authorization;

public record RefreshSession(int UserId, DateTimeOffset ExpiresAt);