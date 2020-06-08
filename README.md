## A Very Simple JWT Validator for use with Cognito.

The Logic can be found in the file [https://github.com/thebeebs/JWTTokenSample/blob/master/src/HelloWorld/JwtValidator.cs](JwtValidator.cs).

To check if a token is valid, create a JwtValidator object with your userPoolId and region. Then call the IsValid function and pass in a token to check. 

```
var region = "eu-west-1";
var userPoolId = "eu-west-1_xxxxxxx";
var validator = new JwtValidator(userPoolId,region);

var test = validator.IsValid(token);
```
