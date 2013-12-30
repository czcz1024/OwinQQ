namespace Owin.Security.QQ
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class QQReturnEndpointContext : ReturnEndpointContext
    {
        public QQReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}