using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Numerics;
using System.Text;
using Newtonsoft.Json;
using Xunit;
using Amazon.Lambda.TestUtilities;
using Amazon.Lambda.APIGatewayEvents;
using Newtonsoft.Json.Linq;

namespace HelloWorld.Tests
{
  public class FunctionTest
  {
    private static readonly HttpClient client = new HttpClient();

 
    private static async Task<string> GetCallingIP()
    {
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Add("User-Agent", "AWS Lambda .Net Client");

            var stringTask = client.GetStringAsync("http://checkip.amazonaws.com/").ConfigureAwait(continueOnCapturedContext:false);

            var msg = await stringTask;
            return msg.Replace("\n","");
    }

    private class TestExpireJwtValidator : JwtValidator
    {
        public bool SkipTokenExpiredValidation
        {
            get => _skipTokenExpiredValidation;
            set => _skipTokenExpiredValidation = value;
        }

        public TestExpireJwtValidator(string userPoolId, string region) : base(userPoolId, region)
        {
        }
    }

    private class TestJwtValidator : JwtValidator
    {

        public bool SkipTokenExpiredValidation
        {
            get => _skipTokenExpiredValidation;
            set => _skipTokenExpiredValidation = value;
        }

        public JToken Token { get; set; }
        
        protected override JToken FetchKey()
        {
            return Token;
        }

        public TestJwtValidator(string userPoolId, string region) : base(userPoolId, region)
        {
        }
    }
    
    [Fact]
    public async Task IsTokenValidWithMockKey()
    {
        // arrange
        const string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6NDAwMDAwMDAwMH0.Z8e6Uq2eSKGmEthU-SETzI7L2s-YQzblt0NHOMxUxfvwMEYjvBK-2amT3JCTuyAb-uAnASxUoGCTG4vOlwHrySfTrRiVSGL38JMWJQJwNf2ivqrRJ7k3M2_-1Qo2yClBcfKAdemAmir27OUtrKKSLhFJA1PvuYzx2hOjgd645oUfzX0qkKbWHzCc-CHm4WoYoKmW9r4G85fca2JtehzcxX3hD7DJeS0_GnKAS0Xh-RutQe8zMJRkP_IX0jQ4VgsrpdiORE3oGyykruXNCqGYBct7EW10nlM_1dtVtd1hzjPPCMOakdrhRzBAdwYUSEqH-qVpWhHZBJYnoJ49uJc9pA";
        var region = string.Empty;
        var userPoolId = string.Empty;

        BigInteger exponantBig = 65537;
        var exponantArray = exponantBig.ToByteArray();

        var modulusString = "9F3CA2B356637CD0746C180A14C4AFBE44EDC25BC1B1A26AED2E7003E933795395A555B091675585AE2CDFC5CCFE96BFCABE3B6AFEFECF75539AF0D1C801DC693F76C214441692EFF5C8F99537894A26F2AFF32B9BF62D8C26555A068E608870AD7C0A2EA3EBFF5D629D6B0091F232B6F1D64F165811C5CB8005C5B94B9A4B7B85F60122350C33193535BF416A92A4C1AF807C9D6DC708DE3B5D4BB4B7C6347BE95FE2CE0EC506B0583EFD27DFF9777472D2F6D5DC09B516D189889BCEC11B087D50A10E9612B537074C232AB6F59B57A2F5D415A4A73197496E07BF8DEA6BE19260E0F6414EBC31BE7DA12936381F81B4E2E92687E66C610682F9B0C8223D33";
        var modulusBig = BigInteger.Parse(
            modulusString,
            NumberStyles.AllowHexSpecifier);
        var modulusArray = modulusBig.ToByteArray();

        Array.Reverse(modulusArray);
        Array.Reverse(exponantArray);

        var validator = new TestJwtValidator(userPoolId, region);
        
        dynamic b = new System.Dynamic.ExpandoObject();
        b.e = Convert.ToBase64String(exponantArray);
        b.n = Convert.ToBase64String(modulusArray);
        validator.Token = JToken.FromObject(b);
        
        // act
        var test = validator.IsValid(token);
        
        // assert
        Assert.True(test);
    }
    [Fact]
    public async Task IsTokenInvalidDueToExpiry()
    {
        // arrange
        
        /*
         Created using: https://jwt.io/ RS256
         Header:
        {
           "alg": "RS256",
           "typ": "JWT",
           "kid" : 1233456
        }
        Payload: 
        {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "exp": 23,
            "email_verified":true 
        }
        
        -----BEGIN PUBLIC KEY-----
           MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
           vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
           aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
           tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
           e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
           V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
           MwIDAQAB
           -----END PUBLIC KEY-----
           
           Used openssl to extract exponant and modulus
           openssl rsa -pubin -in key.pem -text -noout -modulus
        */
        const string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MTIzMzQ1Nn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjIzLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.aCEskCxH7xBYO2W1AHnpE4hYh5Lv0iMI8FjoL65ZkJimjpjb50mfNRdTmQyyppXr-2LcLHLJF6YD_63OO3q4zJQuOTZZvjKTmEwSB9UC4gclLnJr2afZ-hSMM4DKjaBykikSvZERUXAniy3hCXMhMRDCcHBjoFe5vFZ97GIFuyB-7b4yzhlUM1s8PC2wG_Y5mLY_zE2rhtZMhEO3gTkCaL3vZQbafW2W148NuR86t9uOFP_xsbz4d2K329f6LCRvrj1KOdvrPkeJrmAa_5PcphMypM5ybyWeuSOeSIOr1E13YkBbwbMHbpyRROmztroMZjTJgwej0wQ8kiq6pdng9w";
        var region = string.Empty;
        var userPoolId = string.Empty;

        BigInteger exponantBig = 65537;
        var exponantArray = exponantBig.ToByteArray();

        var modulusString = "9F3CA2B356637CD0746C180A14C4AFBE44EDC25BC1B1A26AED2E7003E933795395A555B091675585AE2CDFC5CCFE96BFCABE3B6AFEFECF75539AF0D1C801DC693F76C214441692EFF5C8F99537894A26F2AFF32B9BF62D8C26555A068E608870AD7C0A2EA3EBFF5D629D6B0091F232B6F1D64F165811C5CB8005C5B94B9A4B7B85F60122350C33193535BF416A92A4C1AF807C9D6DC708DE3B5D4BB4B7C6347BE95FE2CE0EC506B0583EFD27DFF9777472D2F6D5DC09B516D189889BCEC11B087D50A10E9612B537074C232AB6F59B57A2F5D415A4A73197496E07BF8DEA6BE19260E0F6414EBC31BE7DA12936381F81B4E2E92687E66C610682F9B0C8223D33";
        var modulusBig = BigInteger.Parse(
            modulusString,
            NumberStyles.AllowHexSpecifier);
        var modulusArray = modulusBig.ToByteArray();

        Array.Reverse(modulusArray);
        Array.Reverse(exponantArray);
        
        dynamic b = new System.Dynamic.ExpandoObject();
        b.e = Convert.ToBase64String(exponantArray);
        b.n = Convert.ToBase64String(modulusArray);

        var validator = new TestJwtValidator(userPoolId, region)
        {
            Token = JToken.FromObject(b)
        };

        // act
        var test = validator.IsValid(token);
        
        validator.SkipTokenExpiredValidation = true;
        var testIgnoreDate = validator.IsValid(token);
        
        // assert
        Assert.False(test);
        Assert.True(testIgnoreDate);
    }

    [Fact]
    public async Task TestHelloWorldFunctionHandler()
    {
            var request = new APIGatewayProxyRequest();
            var context = new TestLambdaContext();
            string location = GetCallingIP().Result;
            Dictionary<string, string> body = new Dictionary<string, string>
            {
                { "message", "hello world" },
                { "location", location },
            };

            var expectedResponse = new APIGatewayProxyResponse
            {
                Body = JsonConvert.SerializeObject(body),
                StatusCode = 200,
                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
            };

            var function = new Function();
            var response = await function.FunctionHandler(request, context);

            Console.WriteLine("Lambda Response: \n" + response.Body);
            Console.WriteLine("Expected Response: \n" + expectedResponse.Body);

            Assert.Equal(expectedResponse.Body, response.Body);
            Assert.Equal(expectedResponse.Headers, response.Headers);
            Assert.Equal(expectedResponse.StatusCode, response.StatusCode);
    }
  }
}