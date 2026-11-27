namespace Notes_App;

public static class AppState
{
    public static WebApplication App { get; set; }
    public static string Issuer { get; set; } = string.Empty;
    public static string JwtSecret { get; set; } = string.Empty;
    public static Byte[] SigningKey { get; set; } 
}