using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Notes_App.Features.JwtTokens;

public class JwtTokenService
{
    public string Create(int userId, string username, string issuer, byte[] signingKey, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
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

    public string CreateOpaqueToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
