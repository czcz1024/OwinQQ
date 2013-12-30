namespace Owin.Security.QQ
{
    using Microsoft.Owin.Security;

    public class QQAuthenticationOptions:AuthenticationOptions
    {
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public string AppID { get; set; }

        public string AppKey { get; set; }

        public string CallbackPath { get; set; }

        public string Host { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IQQAuthenticationProvider Provider { get; set; }

        public QQAuthenticationOptions()
            : base("QQ")
        {
            this.Description.Caption = "QQ User";
            CallbackPath = "/signin-QQ";
        }
    }
}