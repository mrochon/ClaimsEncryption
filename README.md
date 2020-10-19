# Claims Encryption
## Purpose
Provides Azure B2C JWT token confidentiality by encrypting selected claims prior to token issuance and providing support for their decryption by confidential clients for which these tokens are intended.

## Operation
This system consists of two main components:

### REST functions
**/encrypt**: encrypt all properties of a JSON object and return a JSON object with same properties with relavant values encrypted. This operation is used by B2C custom policies to encypt selected claims. The input object **must** include the *aud* claim identifying the target application for the token. This is the application which may call the /decrypt operation. /encrypt does not use any authentication at this time.

**Request**

    POST /encrypt
    Content-type: application/json
    Accept: application/json

    {"aud":"<application id>","property1":"value1"}

**Response**

    {"aud":"<application id>","property1":"CfDJ8OKS0TfF....27hGvaJ0kU3oTTl"}

**/decrypt**: validates signature of the JWT token submitted in the body of the request and decrypts claims which can be validly decrypted. This operation must be called with an OAuth2 token allowing the caller to call this operation (scope=decrypt). The caller's application id (the *azp* claim) must be same as the *aud* claim of the token whose claims need to be decrypted.

**Request**

    POST /decrypt
    Content-type: text/plain
    Accept: application/json
    Authorization: Bearer eyJ0eXAiOiJKV1QiLC...(authorization to call this service, must include *scope=decrypt*)

    eyJ0eXAiOiJKV1QiLC... (token with some encrypted claims)

**Response**

    {"aud":"<application id>","property1":"value1"}

### B2C custom policy

*CryptoExtensions.xml* modifies the standard, local account sign-up/-in journey to encrypt user's display name.

## Deployment



