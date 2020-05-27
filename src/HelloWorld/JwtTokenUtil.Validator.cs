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
        public static bool IsValid(string token, string userPoolId, string region = "eu-west-1")
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
                
            var header =
                Encoding.UTF8.GetString(FromBase64Url(token.Split(".")[0]));
            var keyId = JObject.Parse(header)["kid"].Value<string>();

            var publicKeys = new HttpClient()
                .GetStringAsync(
                    $"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json")
                .Result;
            var json = JObject.Parse(publicKeys);
            var list = new List<JToken>();
            foreach (var jToken in json["keys"]) list.Add(jToken);
            var key = list.First(x =>
                string.Equals(Extensions.Value<string>(x["kid"]), keyId, StringComparison.OrdinalIgnoreCase));

            return IsValidCheck(token, key["n"].Value<string>(), key["e"].Value<string>());
        }

        private static bool IsValidCheck(string token, string publicKeyModulus, string publicKeyExponent)
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

            var expirationSecondsFromUnixEpoch = payloadJson["exp"].Value<double>();
            var t = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            if (t.TotalSeconds > expirationSecondsFromUnixEpoch) return false;
            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter.VerifySignature(hash, FromBase64Url(tokenParts[2]));

        }

        private static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url
                : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }
}

