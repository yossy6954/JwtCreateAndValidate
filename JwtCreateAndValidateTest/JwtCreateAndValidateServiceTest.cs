using JwtCreateAndValidate;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtCreateAndValidateTest
{
    [TestClass]
    public class JwtCreateAndValidateServiceTest
    {
        private JwtCreateAndValidateService Service_;

        public JwtCreateAndValidateServiceTest() {
            Service_ = new JwtCreateAndValidateService() {
                Audience = "TestAudience",
                Issuer = "TestIssuer",
                SigningCredentialsProvider = new SymmetricSecretKeyProvider("MySuperSecretkey!0123456789")
            };
        }

        [TestMethod]
        public void Create_Validate() {
            var sid = Guid.NewGuid().ToString();
            var jwt = Service_.Create(sid, DateTime.UtcNow + TimeSpan.FromHours(1));

            var claims = Service_.Decode(jwt);

            var sid2 = claims.Claims.Where(c => c.Type == ClaimTypes.Sid)
                .FirstOrDefault()?.Value;

            Assert.AreEqual(sid, sid2);
        }

        [TestMethod]
        public void Create_Validate_FailSignature() {
            var sid = Guid.NewGuid().ToString();
            var jwt = Service_.Create(sid, DateTime.UtcNow + TimeSpan.FromHours(1));

            // 違うキーでデコードを行うと失敗
            Service_.SigningCredentialsProvider = new SymmetricSecretKeyProvider("MySuperSecretkey!abcdefghijkl");

            Assert.ThrowsException<SecurityTokenInvalidSignatureException>(() => {
                Service_.Decode(jwt);
            });
        }

        [TestMethod]
        public void Create_Validate_FailIssuer() {
            var sid = Guid.NewGuid().ToString();
            var jwt = Service_.Create(sid, DateTime.UtcNow + TimeSpan.FromHours(1));

            // 違うIssuerでデコードを行うと失敗
            Service_.Issuer = "TestIssuer2";

            Assert.ThrowsException<SecurityTokenInvalidIssuerException>(() => {
                Service_.Decode(jwt);
            });
        }

        [TestMethod]
        public void Create_Validate_FailAudience() {
            var sid = Guid.NewGuid().ToString();
            var jwt = Service_.Create(sid, DateTime.UtcNow + TimeSpan.FromHours(1));

            // 違うAudienceでデコードを行うと失敗
            Service_.Audience = "TestAudience2";

            Assert.ThrowsException<SecurityTokenInvalidAudienceException>(() => {
                Service_.Decode(jwt);
            });
        }
    }
}
