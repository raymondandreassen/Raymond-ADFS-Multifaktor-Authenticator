using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace Raymond.ADFS_MFA
{
    class AuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
    {
        // These properties are used to 'learn' AD FS about your Authentication Provider.

        public AuthenticationAdapterMetadata()
        {

        }


        public string[] AuthenticationMethods
        {
            /* This should return a list (array) of strings, where each string is a supported authentication method. 
             * If, after successful authentication, the TryEndAuthentication method in the IAuthenticationAdapter interface return success, 
             * this methods must contain a claim of type http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod. 
             * The value of this claim should be one of authentication methods listed in the property. 
             * In our sample Authentication Adapter we support only one authentication method; http://schemas.microsoft.com/ws/2012/12/authmethod/otp.
             * */

            get { return new string[] { "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" }; }
        }

        public string[] IdentityClaims
        {
            /* This property should contain the claim types that your Authentication Adapter requires. 
             * These claims, and values, are passed to multiple methods in the IAuthenticationAdapter. 
             * My testing revealed that only the FIRST one you enter here is presented to the adapter; so we will use UPN here.
             * */

            get { return new string[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" }; }
        }

        public string AdminName
        {
            // This is the friendly name of the Authentication Provider, shown to AD FS admins in the AD FS GUI.

            get { return "Raymonds Multifaktor Authentisering"; }
        }

        public int[] AvailableLcids
        {
            /* This property should contain all the lcid's (or languages) that your Authentication Adapter supports. 
             * We'll only implement lcid 1033 on our sample Authentication Adapter.
             * */

            get { return new int[] { 1033, 1044 }; }

            // 1033 - English
            // 1044 - Norsk bokmål
            // http://msdn.microsoft.com/en-us/goglobal/bb964664.aspx
        }

        public Dictionary<int, string> Descriptions
        {
            /* This property should contain a list of descriptions for the Authentication Adapter, per language. I haven't seen this being used anywhere in AD FS…
             * */
            get
            {
                Dictionary<int, string> result = new Dictionary<int, string>
                {
                    { 1033, "My Authentication Provider :: Descriptions" },
                    { 1044, "My Authentication Provider :: Beskrivelse" }
                };
                return result;
            }
        }

        //public int ReturnLCID(int lcid)
        //{
        //    // Make sure that it is a valid LCID, if not return 1033 - English
        //    if (AvailableLcids.Contains(lcid)) return lcid;
        //    else return 1033;
        //}

        public Dictionary<int, string> FriendlyNames
        {
            /* If multiple Authentication Adapters (MFA providers) are available for a user, a form us presented to the user 
             * where he or she can chose how to perform additional authentication. The strings in this property (per language) 
             * that are used to identify your Authentication Adapter in that form.
             * */

            get
            {
                Dictionary<int, string> result = new Dictionary<int, string>
                {
                    { 1033, "UiT : Multifactor authentication" },
                    { 1044, "UiT : Multifaktor autentisering" }
                };
                return result;
            }
        }

        public bool RequiresIdentity
        {
            /* This is an indication whether or not the Authentication Adapter requires an Identity Claim or not. 
             * If you require an Identity Claim, the claim type must be presented through the IdentityClaims property.
             * */

            get { return true; }
        }
    }
}





