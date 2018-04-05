using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtCreateAndValidate
{
    public class JwtCreateAndValidateService
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public ISigningCredentialsProvider SigningCredentialsProvider { get; set; }

        public string Create(string sid, DateTime expire) {
            var jwt = new JwtSecurityToken(
                issuer: Issuer,
                audience: Audience,
                claims: new List<Claim>() {
                    new Claim(ClaimTypes.Sid, sid),
                },
                expires: expire,
                signingCredentials: SigningCredentialsProvider.GetSigningCredentials()
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(jwt);

        }

        public ClaimsPrincipal Decode(string token) {
            var tokenValidationParameters = new TokenValidationParameters {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = SigningCredentialsProvider.GetVerificationKey(),
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidAudience = Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwt = tokenHandler.ReadToken(token) as JwtSecurityToken;
            return tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        }
    }
}
