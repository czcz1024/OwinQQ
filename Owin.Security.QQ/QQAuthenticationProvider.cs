namespace Owin.Security.QQ
{
    using System;
    using System.Threading.Tasks;

    public class QQAuthenticationProvider : IQQAuthenticationProvider
    {
        public Func<QQAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<QQReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public QQAuthenticationProvider()
        {
            this.OnAuthenticated = (context => Task.FromResult((object)null));
            this.OnReturnEndpoint = (context => Task.FromResult((object)null));
        }

        public Task Authenticated(QQAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public Task ReturnEndpoint(QQReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}