using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace HelloWorld
{
    public class JwtValidator
    {
        private readonly string _userPoolId;
        private readonly string _region;
        private readonly bool _skipTokenExpiredValidation;
        private JToken _key;

        public JwtValidator(string userPoolId, string region, bool skipTokenExpiredValidation = false)
        {
            _userPoolId = userPoolId;
            _region = region;
            _skipTokenExpiredValidation = skipTokenExpiredValidation;
        }
        
        public bool IsValid(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
                
            var header =
                Encoding.UTF8.GetString(FromBase64Url(token.Split(".")[0]));
            var keyId = JObject.Parse(header)["kid"].Value<string>();
            _key = GetKey(keyId);

            return IsValidCheck(token, _key["n"].Value<string>(), _key["e"].Value<string>());
        }

        private JToken GetKey(string keyId)
        {
            var publicKeys = new HttpClient()
                .GetStringAsync(
                    $"https://cognito-idp.{_region}.amazonaws.com/{_userPoolId}/.well-known/jwks.json")
                .Result;
            var json = JObject.Parse(publicKeys);
            var list = new List<JToken>();
            foreach (var jToken in json["keys"])
            {
                list.Add(jToken);
            }

            var key = list.First(x =>
                string.Equals(Extensions.Value<string>(x["kid"]), keyId, StringComparison.OrdinalIgnoreCase));
            return key;
        }

        private bool IsValidCheck(string token, string publicKeyModulus, string publicKeyExponent)
        {
            var tokenParts = token.Split('.');

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters
                {
                    Modulus = FromBase64Url(publicKeyModulus),
                    Exponent = FromBase64Url(publicKeyExponent)
                });

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            var payloadJson = JObject.Parse(Encoding.UTF8.GetString(FromBase64Url(tokenParts[1])));
            if (!payloadJson["email_verified"].Value<bool>())
            {
                return false;
            }

            if (IsTokenExpired(payloadJson["exp"].Value<double>())) return false;
            
            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter.VerifySignature(hash, FromBase64Url(tokenParts[2]));

        }

        private bool IsTokenExpired(double expirationSecondsFromUnixEpoch)
        {
            if (this._skipTokenExpiredValidation) return false;
            var t = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return (t.TotalSeconds > expirationSecondsFromUnixEpoch);
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            var incoming = base64Url
                .Replace('_', '/').Replace('-', '+');
            if (base64Url.Length % 4 == 2)
                incoming += "==";
            else if (base64Url.Length % 4 == 3) incoming += "=";

            return Convert.FromBase64String(incoming);
        }
    }
}

