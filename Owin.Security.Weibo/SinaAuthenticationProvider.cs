namespace Owin.Security.Weibo
{
    using System;
    using System.Threading.Tasks;

    public class SinaAuthenticationProvider : ISinaAuthenticationProvider
    {
        public SinaAuthenticationProvider()
        {
            this.OnAuthenticated = (context => Task.FromResult((object)null));
            this.OnReturnEndpoint = (context => Task.FromResult((object)null));
        }

        public Func<SinaAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<SinaReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Task Authenticated(SinaAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public Task ReturnEndpoint(SinaReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}