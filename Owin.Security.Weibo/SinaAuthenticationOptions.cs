namespace Owin.Security.Weibo
{
    using Microsoft.Owin.Security;

    public class SinaAuthenticationOptions : AuthenticationOptions
    {
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public string AppID { get; set; }

        public string AppKey { get; set; }

        public string CallbackPath { get; set; }

        public string Host { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISinaAuthenticationProvider Provider { get; set; }
        public SinaAuthenticationOptions()
            : this("SinaWeibo")
        {
            
        }

        public SinaAuthenticationOptions(string authenticationType)
            : base(authenticationType)
        {
            this.Description.Caption = "Weibo User";
            CallbackPath = "/signin-sinaweibo";
        }
    }
}