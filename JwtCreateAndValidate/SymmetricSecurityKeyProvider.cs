using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JwtCreateAndValidate
{
    public interface ISigningCredentialsProvider {
        /// <summary>
        /// 署名検証用キーの取得
        /// </summary>
        /// <returns></returns>
        SecurityKey GetVerificationKey();

        /// <summary>
        /// 署名作成用アルゴリズムの取得
        /// </summary>
        /// <returns></returns>
        SigningCredentials GetSigningCredentials();
    }

    public class SymmetricSecretKeyProvider : ISigningCredentialsProvider {
        private string SecretKey { get; set; }

        public SymmetricSecretKeyProvider(string secretKey) {
            SecretKey = secretKey;
        }

        public SecurityKey GetVerificationKey() {
            return new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(SecretKey)
                    );
        }

        public SigningCredentials GetSigningCredentials() {
            return new SigningCredentials(
                    GetVerificationKey(),
                    SecurityAlgorithms.HmacSha256
                );
        }
    }
}
