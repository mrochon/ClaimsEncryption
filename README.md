# Claims Encryption
## Purpose
Provides Azure B2C JWT token confidentiality by encrypting selected claims prior to token issuance and providing support for their decryption by confidential clients for which these tokens were intended.

## Operation
This system consists of two main components: a web application providing the encryption/decryption operations and B2C policies calling the encryption operation.

### REST functions
**/encrypt**: encrypt all properties of a JSON object and return a JSON object with same properties with relavant values encrypted. This operation is used by B2C custom policies to encypt selected claims. The input object **must** include the *aud* claim identifying the target application for the token. This is the application which may call the /decrypt operation. /encrypt does not use any authentication at this time.

**Request**

    POST /encrypt
    Content-type: application/json
    Accept: application/json

    {"aud":"<application id>","property1":"value1"}

**Response**

    {"aud":"<application id>","property1":"CfDJ8OKS0TfF....27hGvaJ0kU3oTTl"}

**/decrypt**: validates signature of the JWT token submitted in the body of the request and decrypts claims which can be validly decrypted. This operation must be called with an OAuth2 token allowing the caller to call this operation (*roles* claim **must** include *decrypt* role). The caller's application id (the *azp* claim) must be same as the *aud* claim of the token whose claims need to be decrypted.

**Request**

    POST /decrypt
    Content-type: text/plain
    Accept: application/json
    Authorization: Bearer eyJ0eXAiOiJKV1QiLC...(authorization to call this service, must include *scope=decrypt*)

    eyJ0eXAiOiJKV1QiLC... (token with some encrypted claims)

**Response**

    {"aud":"<application id>","property1":"value1"}

### B2C custom policy

*CryptoExtensions.xml* modifies the standard, local account sign-up/-in journey to encrypt user's display name. The call to the encrypt operation looks as follows. **Note** the inclusion of the *aud* claim in the request.

(B2C policies used in this sample use the [IEF upload tool](https://github.com/mrochon/b2cief-upload) to resolve tenant name, IEF app ids and symbolic parameters like *{RESTEncryptUrl}* below).

    <ClaimsProvider>
      <DisplayName>REST APIs</DisplayName>
      <TechnicalProfiles>
        <TechnicalProfile Id="REST-Encrypt">
          <DisplayName>Encrypt selected claims</DisplayName>
          <Protocol Name="Proprietary" Handler="Web.TPEngine.Providers.RestfulProvider, Web.TPEngine, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
          <Metadata>
            <Item Key="ServiceUrl">{RESTEncryptUrl}/encrypt</Item>
            <Item Key="SendClaimsIn">Body</Item>
            <!-- Set AuthenticationType to Basic or ClientCertificate in production environments -->
            <Item Key="AuthenticationType">None</Item>
            <!-- REMOVE the following line in production environments -->
            <Item Key="AllowInsecureAuthInProduction">true</Item>
          </Metadata>
          <InputClaims>
            <!-- aud MUST be sent as input claim -->
            <InputClaim ClaimTypeReferenceId="aud" DefaultValue="{OIDC:ClientId}" AlwaysUseDefaultValue="true" />          
            <!-- Other claims to be encrypted -->
            <InputClaim ClaimTypeReferenceId="displayName" />
          </InputClaims>
          <OutputClaims>
            <!-- Returned encrypted claims -->
            <OutputClaim ClaimTypeReferenceId="displayName" />
          </OutputClaims>
          <UseTechnicalProfileForSessionManagement ReferenceId="SM-Noop" />
        </TechnicalProfile>
      </TechnicalProfiles>
    </ClaimsProvider>

You can run this policy using this [link](https://mrochonb2cprod.b2clogin.com/mrochonb2cprod.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1A_CRYPTOsignup_signin&client_id=68f6e047-5204-471a-b94b-b0df615e8ea0&nonce=defaultNonce&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug&scope=openid&response_type=id_token&prompt=login). The entered *Display Name* will show as encypted in the displayed token.

## Deployment

TBD

