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
        // The IAdapterPresentation interface defines how the Authentication Adapter 'presents' itself to the user.
        // 
        // The IAdapterPresentationForm is very much like the IAdapterPresentation, but this interface let's you define what 
        // and how you want to ask the user for additional authentication. In our example, we want the user to input a PIN in the sign-in page.

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

        //private string message = "";
        private bool isPermanentFailure;

        private string upn;
        private string secretKey;

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




            string result = "";
            if (!String.IsNullOrEmpty(this.message))
            {
                result += "<p>" + message + "</p>";
            }
            if (!this.isPermanentFailure)
            {
                result += "<form method=\"post\" id=\"loginForm\" autocomplete=\"off\">";
                result += "PIN: <input id=\"pin\" name=\"pin\" type=\"password\" />";
                result += "<input id=\"context\" type=\"hidden\" name=\"Context\" value=\"%Context%\"/>";
                result += "<input id=\"authMethod\" type=\"hidden\" name=\"AuthMethod\" value=\"%AuthMethod%\"/>";
                result += "<input id=\"continueButton\" type=\"submit\" name=\"Continue\" value=\"" + buttonContinue + "\" />";
                result += "</form>";
            }

            return result;
            
        }

        public string GetFormPreRenderHtml(int lcid)
        {
            /* This method is used to allow the Authentication Adapter to insert any special tags etc. in the <head> element of 
             * the AD FS sign-in page. Again, with the same lcid value to localize your pages.
             * 
             * The method should return the HTML code you want to insert in the HTML <head> element of AD FS the sign-in page.
             * */

            // return string.Empty;
            return "<meta name=\"author\" content=\"Raymond Andreassen\"><meta name=\"Time\" content=\"" + DateTime.Now.ToShortTimeString() + "\">";
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
