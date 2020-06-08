using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace HelloWorld
{
    public class JwtValidator
    {
        private readonly string _userPoolId;
        private readonly string _region;
        protected bool _skipTokenExpiredValidation;
        private byte[] _publicKeyModulus;
        private byte[] _publicKeyExponent;
        private string _headerRaw;
        private string _bodyRaw;
        private string _header;
        private string _body;
        private byte[] _signature;
        private string _keyId;
        private double _exp;
        private bool _verified;

        public JwtValidator(string userPoolId, string region)
        {
            _userPoolId = userPoolId;
            _region = region;
        }

        public bool IsValid(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;

            var parts = token.Split(".");
            _headerRaw = parts[0];
            _bodyRaw = parts[1];
            _header = Encoding.UTF8.GetString(FromBase64Url(parts[0]));
            _body = Encoding.UTF8.GetString(FromBase64Url(parts[1]));
            _signature = FromBase64Url(parts[2]);
            var payloadJson = JObject.Parse(_body);
            _verified = payloadJson["email_verified"].Value<bool>();
            _exp = payloadJson["exp"].Value<double>();
            
            SetKey(JObject.Parse(_header)["kid"].Value<string>());
            
            return IsValidCheck();
        }

        private void SetKey(string keyId)
        {
            _keyId = keyId;
            var key = FetchKey();
            _publicKeyModulus = FromBase64Url(key["n"].Value<string>());
            _publicKeyExponent = FromBase64Url(key["e"].Value<string>());
        }

        protected virtual JToken FetchKey()
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
                string.Equals(x["kid"].Value<string>(), _keyId, StringComparison.OrdinalIgnoreCase));
            return key;
        }

        private bool IsValidCheck()
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                                   new RSAParameters
                                   {
                                       Modulus = _publicKeyModulus,
                                       Exponent = _publicKeyExponent
                                   });

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(_headerRaw + '.' + _bodyRaw));

            if (!_verified) return false;
            if (IsTokenExpired()) return false;

            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter.VerifySignature(hash, _signature);
        }

        private bool IsTokenExpired()
        {
            if (_skipTokenExpiredValidation) return false;
            var t = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return (t.TotalSeconds > _exp);
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

