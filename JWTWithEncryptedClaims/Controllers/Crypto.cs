using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.Identity.Web.Resource;

namespace JWTWithEncryptedClaims.Controllers
{
    [ApiController]
    [Route("")]
    public class Crypto : ControllerBase
    {
        private readonly ILogger<Crypto> _logger;
        IDataProtectionProvider _protectionProvider;

        public Crypto(ILogger<Crypto> logger, IDataProtectionProvider protectionProvider)
        {
            _logger = logger;
            _protectionProvider = protectionProvider;
        }

        [HttpPost("encrypt")]
        public async Task Encrypt([FromBody] object inputClaims) // must be a JSON object, must include clientId property
        {
            var inp = JObject.Parse(inputClaims.ToString());
            var aud = inp["aud"].Value<string>();
            if (String.IsNullOrEmpty(aud))
                throw new Exception("aud value is missing");
            var protector = _protectionProvider.CreateProtector(aud);
            Response.ContentType = "application/json";
            Response.StatusCode = 200;
            var outObject = new JObject();
            foreach (var claim in inp)
            {
                if (String.Compare(claim.Key, "aud") == 0)
                    outObject.Add(claim.Key, claim.Value.ToString());
                else
                    outObject.Add(claim.Key, protector.Protect(claim.Value.ToString()));
            }
            await Response.WriteAsync(outObject.ToString());
            await Response.CompleteAsync();
        }

        [Authorize(Roles ="decrypt")]
        [HttpPost("decrypt")]
        public async Task Decrypt() 
        {
            Request.HttpContext.VerifyUserHasAnyAcceptedScope("decrypt");
            var jwt = "";
            using (var reader = new StreamReader(Request.Body))
            {
                jwt = await reader.ReadToEndAsync();
            }
            var appId = User.FindFirst("azp").Value;
            var principal = await ValidateTokenSignature(jwt);
            var aud = principal.FindFirst("aud").Value;
            if (appId != aud) throw new Exception("Calling client's id must be same as encrypted token's audience");
            var protector = _protectionProvider.CreateProtector(aud);
            var outObject = new JObject();
            foreach (var claim in principal.Claims)
            {
                if (claim.Type == "aud")
                    outObject.Add("aud", claim.Value.ToString());
                else
                {
                    try
                    {
                        outObject.Add(claim.Type, protector.Unprotect(claim.Value.ToString()));
                    } catch(CryptographicException)
                    {
                        outObject.Add(claim.Type, claim.Value.ToString());
                    }
                }
            }
            await Response.WriteAsync(outObject.ToString());
            await Response.CompleteAsync();
        }
        private async Task<ClaimsPrincipal> ValidateTokenSignature(string jwt)
        {
            // V2.0 tokens use GUID for aud; V1.0 use URI, when received from V2.0 endpoint??? - not sure
            var validator = new JwtSecurityTokenHandler();
            if (validator.CanReadToken(jwt))
            {
                try
                {
                    var bodyEncoded = jwt.Split('.')[1];
                    while ((bodyEncoded.Length % 4) != 0)
                    {
                        bodyEncoded += "=";
                    }
                    var bodyBytes = System.Convert.FromBase64String(bodyEncoded);
                    var body = JObject.Parse(System.Text.Encoding.UTF8.GetString(bodyBytes));
                    var issuer = body["iss"].Value<string>(); // e.g. "https://mrochonb2cprod.b2clogin.com/cf6c572c-c72e-4f31-bd0b-75623d040495/v2.0/"
                    issuer = issuer.Substring(0, issuer.Length - 5); // remove trailing "v2.0/"
                    var journeyName = body["acr"].Value<string>(); // e.g. "b2c_1a_cryptosignup_signin"
                    SecurityToken validatedToken;
                    var optsHandler = new JwtBearerPostConfigureOptions();
                    var options = new JwtBearerOptions() 
                    { 
                        Authority = $"{issuer}{journeyName}/v2.0/"
                        /*, MetadataAddress = "" */
                    };
                    optsHandler.PostConfigure("JWTBearer", options);
                    var conf = await options.ConfigurationManager.GetConfigurationAsync(new System.Threading.CancellationToken());
                    options.TokenValidationParameters.IssuerSigningKeys = conf.SigningKeys;
                    options.TokenValidationParameters.ValidateAudience = false;
                    options.TokenValidationParameters.ValidateIssuer = false;
                    //options.TokenValidationParameters.ValidateIssuerSigningKey = false;
                    var principal = validator.ValidateToken(jwt, options.TokenValidationParameters, out validatedToken);
                    return principal;
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
            return null;
        }
    }
}

