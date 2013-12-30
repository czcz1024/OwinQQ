namespace Owin.Security.Weibo
{
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    public class SinaAuthenticationMiddleware : AuthenticationMiddleware<SinaAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public SinaAuthenticationMiddleware(OwinMiddleware next,IAppBuilder app, SinaAuthenticationOptions options)
            : base(next, options)
        {
            this._logger = AppBuilderLoggerExtensions.CreateLogger<SinaAuthenticationMiddleware>(app);
            if (options.Provider == null)
            {
                options.Provider = new SinaAuthenticationProvider();
            }

            if (this.Options.StateDataFormat == null)
            {
                this.Options.StateDataFormat = new PropertiesDataFormat(app.CreateDataProtector(typeof(SinaAuthenticationMiddleware).FullName, this.Options.AuthenticationType, "v1"));
            }
            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
                this.Options.SignInAsAuthenticationType = AppBuilderSecurityExtensions.GetDefaultSignInAsAuthenticationType(app);


            this._httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options));

            this._httpClient.MaxResponseContentBufferSize = 10485760L;
        }

        protected override AuthenticationHandler<SinaAuthenticationOptions> CreateHandler()
        {
            return new SinaAuthenticationHandler(this._httpClient, this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(SinaAuthenticationOptions options)
        {
            return new WebRequestHandler();
        }
    }
}