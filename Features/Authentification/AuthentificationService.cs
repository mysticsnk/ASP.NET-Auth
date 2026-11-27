using Notes_App.Features.Authorization;
using Notes_App.Features.Users;

namespace Notes_App.Features.Authentification;

public class AuthentificationService
{
    public IResult Login(LoginRequest? request)
    {
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        var userService = AppState.App.Services.GetRequiredService<UserService>();
        var user = userService.Authenticate(request?.Username, request?.Password);
        return user is null ? Results.Unauthorized() : Results.Ok(authorizationService.CreateTokenPair(user));
    }
    
    
    
    
}