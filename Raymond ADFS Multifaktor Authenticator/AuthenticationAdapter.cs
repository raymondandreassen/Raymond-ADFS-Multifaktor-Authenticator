using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace Raymond.ADFS_MFA
{
    class AuthenticationAdapter : IAuthenticationAdapter
    {
        public IAuthenticationAdapterMetadata Metadata
        {
            /* Metadata is used by AD FS to learn about your Authentication Provider 
             * (just like the FederationMetadata.xml can be used by AD FS to learn about a relying party or claims provider).
             * The property should 'return' a variable of a type that implements IAuthenticationAdapterMetadata. 
             * One example would be that you can 'tell' AD FS what the Identity Claim is your authentication adapter expects 
             * when the methods like BeginAuthentication and IsAvailableForUser that are called by AD FS.
             * */

            get { return new AuthenticationAdapterMetadata(); }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            /* This method is called by AD FS once AD FS decides that Multi-Factor Authentication is required (and available) for a user. 
             * It will pass the Identity Claim to the Authentication Adapter.
             * The Authentication Adapter decides on what this identity claim should be. 
             * Think of a UPN or SAM Account Name.AD FS also passes the context of the authentication request.
             * This context store data required by AD FS and the Authentication Adapter to perform and complete the authentication.
             *
             * The method has to return a variable that implements the IAdapterPresentation interface. 
             * This return-type contains information that AD FS uses to build the proper web page to authenticate the user (during a browser based logon). 
             * Let's say you want the ask the user for a PIN, then we have to create a few lines of HTML code that show this input box, 
             * together with an appropriate text, to the end-user. That's just what this return value does.
             * */

            IAdapterPresentation authPres;

            string upn = identityClaim.Value;
            string secretKey = TOTPAuthenticator.GetSecretKey(upn);
            context.Data.Add("upn", upn);

            if (string.IsNullOrEmpty(secretKey))
            {
                secretKey = TOTPAuthenticator.GenerateSecretKey();
                TOTPAuthenticator.SetSecretKey(upn, secretKey);
                authPres = new AdapterPresentation(upn, secretKey);
            }
            else
            {
                authPres = new AdapterPresentation();
            }
            return authPres;
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            /* The IsAvailableForUser method returns either true or false and is an indication to AD FS that your Authentication Adapter 
             * can actually perform Multi-Factor Authentication for the user. 
             * In order to decide whether to return true or false, an identity claim is passed from AD FS to the Authentication Provider. 
             * Check the IAdapterPresentation method we will cover in a few moments for the usage of the identity claim (identityClaim) and authentication context (context).
             * The method should return true if this Authentication Provider can handle authentication for this identity, or user, and false when it can not.
             * */

            return true;
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            /* The OnAuthenticationPipelineLoad method is called whenever the Authentication Provider is loaded by AD FS into it's pipeline. 
             * It allows your adapter to initialize itself. AD FS will 'tell' your adapter which information AD FS has. 
             * The IAuthenticationMethodConfigData contains a single property called Data. 
             * For the developers; this property is of type Stream. In our sample Authentication Provider will not use this configData.
             * The method returns nothing.
             * */
        }

        public void OnAuthenticationPipelineUnload()
        {
            /* The OnAuthenticationPipelineUnload is called by AD FS whenever the Authentication Provider is unloaded from 
             * the AD FS pipeline and allows the Authentication Adapter to clean up anything it has to clean up.
             * The method returns nothing.
             * */
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            /* The OnError method is called whenever something goes wrong in the authentication process. 
             * To be more precise; if anything goes wrong in the BeginAuthentication or TryEndAuthentication methods of the authentication adapter, 
             * and either of these methods throw an ExternalAuthenticationException, the OnError method is called. 
             * This allows your adapter to capture the error and present a nice error message to the customer.
             *
            * Because we have to present a nice error message to the user, this method returns an instance of a class that implements IAdapterPresentation. 
            * We've touched that interface before. 
            * */

            return new AdapterPresentation(string.Format("<p>{0}</p>", ex.Message), true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
        {
            /* This method is called by AD FS when the Authentication Adapter should perform the actual authentication. 
             * It will pass the IAuthenticationContext to the method, which we have seen before. 
             * It will also pass the proofData variable, that implements IProofData. 
             * This is a dictionary of strings to objects, that represents whatever you have asked the customer for during the BeginAuthentication method. 
             * 
             * The method allows you to use the "claims" out parameter. If the Authentication Adapter has successfully performed the authentication, 
             * this variable should contain at least one claim with type http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod. 
             * The value of this claim should contain the method of authentication used. 
             * It must be one of the values listed in the AuthenticationMethods parameter of the class that implements IAuthenticationAdapterMetadata. 
             * 
             * The method returns a variable of a type that implements IAdapterPresentation. 
             * Typically, when authentication has succeeded you add the proper authentication method claim to the claims out parameter, and return null. 
             * Whenever authentication has failed, you can create a nice error message for the user and return this in the return variable. 
             * */

            if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey("ChallengeQuestionAnswer") || context == null || context.Data == null || !context.Data.ContainsKey("upn") || string.IsNullOrEmpty((string)context.Data["upn"]))
            {
                throw new ExternalAuthenticationException("No answer found or corrupted context.", context);
            }

            claims = null;
            IAdapterPresentation result = null;
            string upn = (string)context.Data["upn"];
            string code = (string)proofData.Properties["ChallengeQuestionAnswer"];

            if (TOTPAuthenticator.CheckCode(upn, code))
            {
                System.Security.Claims.Claim claim = new System.Security.Claims.Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2012/12/authmethod/otp");
                claims = new System.Security.Claims.Claim[] { claim };
            }
            else
            {
                result = new AdapterPresentation();
            }
            return result;
        }
    }
}
