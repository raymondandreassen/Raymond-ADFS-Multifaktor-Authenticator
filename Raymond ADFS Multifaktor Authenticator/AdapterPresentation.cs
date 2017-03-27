using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Web.Authentication.External;


namespace Raymond.ADFS_MFA
{
    public class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        /* The IAdapterPresentation interface defines how the Authentication Adapter 'presents' itself to the user.
        * 
        * The IAdapterPresentationForm is very much like the IAdapterPresentation, but this interface let's you define what 
        * and how you want to ask the user for additional authentication. In our example, we want the user to input a PIN in the sign-in page.
        * */

        private string message = "";
        private bool isPermanentFailure;
        private string upn;
        private string secretKey;



        public AdapterPresentation()
        {
            this.message                = string.Empty;
            this.isPermanentFailure     = false;
        }

        public AdapterPresentation(string message, bool isPermanentFailure)
        {
            this.message = message;
            this.isPermanentFailure = isPermanentFailure;
        }

        public AdapterPresentation(string upn = null, string secretKey = null)
        {
            this.upn = upn;
            this.secretKey = secretKey;
        }

        public string GetFormHtml(int lcid)
        {
            /* The GetFormHtml is used to represent the HTML code that is inserted in the AD FS sing-in page. 
             * The lcid code passed allows you to localize the page.
             * 
             * The method should return the string, plain old HTML, that represents the code for whatever you want to do in the sing-in page.
             * One important thing to note here though; It could very well be the case that a user that is authentication, 
             * is first hitting one server in the farm, enters the PIN and submits the PIN. 
             * This postback to the server could hit another server in the farm. 
             * Now the context of the logon would be lost. AD FS cannot rely on session state or anything like that. 
             * We need to 'manually' transfer the context of the logon together with the proof data that the customer provided.
             * So if we need to use a form, make sure to include a hidden input element, that contains the context of the request. 
             * This is best done through a constructor that can be called from the BeginAuthentication and TryEndAuthentication methods in the AuthenticationAdapter implementation.
             * Also, if we have multiple Authentication Providers enables simultaneously for a Relying Party, we need to identify our own provider.
             * This is done through a hidden form field called authMethod. So, whatever you do here, make sure you include at least two form fields; context and authMethod.
             * */

            // Get the correct template by LCID
            string htmlTemplate = "";
            string htmlMessage = "";


            switch(lcid)
            {
                case 1033: {    htmlTemplate = Raymond.ADFS_MFA.Properties.Resources.AuthenticationForm_1033;
                                htmlMessage = Raymond.ADFS_MFA.Properties.Resources.WebForm_1033;
                                break; }
                case 1044: {    htmlTemplate = Raymond.ADFS_MFA.Properties.Resources.AuthenticationForm_1044;
                                htmlMessage = Raymond.ADFS_MFA.Properties.Resources.WebForm_1044;
                                break; }
                default:   {    htmlTemplate = Raymond.ADFS_MFA.Properties.Resources.AuthenticationForm_1033;
                                htmlMessage = Raymond.ADFS_MFA.Properties.Resources.WebForm_1033;
                                break; }
            }
            

            if (!String.IsNullOrEmpty(this.message))
            {
                htmlTemplate = htmlTemplate.Replace("ERRORMSG", message);
            }
            if (!this.isPermanentFailure)
            {
                if (string.IsNullOrEmpty(this.secretKey))
                {
                    htmlTemplate = htmlTemplate.Replace("ERRORMSG", "");
                    htmlTemplate = htmlTemplate.Replace("PICTUREHERE", "");
                }
                else
                {
                    htmlTemplate = htmlTemplate.Replace("ERRORMSG", "");
                    string htmlSecret = Raymond.ADFS_MFA.Properties.Resources.WebFormSecret;

                    int width = 100;
                    int height = 100;

                    htmlSecret = String.Format(htmlSecret, this.upn, this.secretKey, Properties.Resources.SecretIssuer);
                    // otpauth://totp/UiT Office 365 pålogging:{0}?secret={1}
                    // otpauth://totp/UiT Secure Logon ({0})?secret={1}&issuer={2}&algorithm={3}&digits={4}&period={5}

                    htmlTemplate = htmlTemplate.Replace("PICTUREHERE", String.Format(htmlMessage, width, height, System.Web.HttpUtility.UrlEncode(htmlSecret)));

                    
                    //htmlSecret = System.Web.HttpUtility.UrlEncode(htmlSecret);
                    //htmlTemplate = htmlTemplate.Replace("SECRETHERE", htmlSecret);
                }
            }

            return htmlTemplate;
            
        }

        public string GetFormPreRenderHtml(int lcid)
        {
            /* This method is used to allow the Authentication Adapter to insert any special tags etc. in the <head> element of 
             * the AD FS sign-in page. Again, with the same lcid value to localize your pages.
             * 
             * The method should return the HTML code you want to insert in the HTML <head> element of AD FS the sign-in page.
             * */

            // return string.Empty;
            return string.Format($"        <meta name=\"author\" content=\"UiT MFA - Raymond Andreassen 2017\"> \r\n" +
                   $"        <meta name=\"Time\" content=\"{DateTime.Now.ToShortTimeString()}\"> \r\n" +
                   $"        <meta name=\"About\" content=\"UiT Time-Based (RFC6238) One-Time Password (RFC4226) Authentication Provider\"> \r\n" +
                   $"        <meta name=\"LCID\" content=\"{0}\"> \r\n\r\n", lcid);
                   
        }

        public string GetPageTitle(int lcid)
        {
            /* The GetPageTitle method is used by AD FS to query to Authentication Adapter for the title of the authentication page. 
             * It passes an integer called lcid that represents the browser language setting of the user. 
             * For example, value '1033' is for English – United States. 
             * To learn more about these lcid values, or Locale ID's, please check out this page; http://msdn.microsoft.com/en-us/goglobal/bb964664.aspx 
             * By passing this lcid value, AD FS allows you to create a user interface in multiple languages. 
             * 
             * This GetPageTitle string will actually go into the <title> element of the logon page.
             * 
             * The method returns a string; the title of the page.
             * */

            string pTitle = "";
            switch(lcid)
            {
                case 1033:  { pTitle = "UiT Multifactor Authentication"; break; }
                case 1044:  { pTitle = "UiT Multifaktor Autentisering"; break; }
                default:    { pTitle = "UiT Multifactor Authentication"; break; }
            }
            return pTitle;
        }
    }
}
