namespace Owin.Security.Weibo
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class SinaReturnEndpointContext : ReturnEndpointContext
    {
        public SinaReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}