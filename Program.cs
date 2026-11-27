using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Notes_App;
using Notes_App.Features.Authentification;
using Notes_App.Features.Authorization;
using Notes_App.Features.JwtTokens;
using Notes_App.Features.Notes;
using Notes_App.Features.Users;

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["Jwt:Issuer"];
AppState.Issuer = issuer;
var secret = builder.Configuration["Jwt:SecretKey"];
AppState.JwtSecret = secret;

if (string.IsNullOrWhiteSpace(issuer))
    throw new InvalidOperationException("Configuration value 'Jwt:Issuer' is required.");
if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
    throw new InvalidOperationException("'Jwt:SecretKey' must contain at least 32 UTF-8 bytes.");

var signingKey = Encoding.UTF8.GetBytes(secret);
AppState.SigningKey = signingKey;

builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<NoteService>();
builder.Services.AddSingleton<AuthentificationService>();
builder.Services.AddSingleton<AuthorizationService>();
builder.Services.AddSingleton<JwtTokenService>();
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
AppState.App = app;
var authentificationService = AppState.App.Services.GetRequiredService<AuthentificationService>();
var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    message = "Private notes API",
    endpoints = new[] { "POST /login", "POST /refresh", "GET /notes", "GET /notes/{id}", "POST /notes", "PUT /notes/{id}", "DELETE /notes/{id}" }
}));

app.MapPost("/login", authentificationService.Login);
app.MapPost("/refresh", authorizationService.Refresh);
var api = app.MapGroup("/");
api.MapNoteEndpoints();

app.Run();

