namespace Owin.Security.QQ
{
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using Owin;

    public class QQAuthenticationMiddleware : AuthenticationMiddleware<QQAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        public QQAuthenticationMiddleware(OwinMiddleware next,IAppBuilder app, QQAuthenticationOptions options)
            : base(next, options)
        {
            this._logger = AppBuilderLoggerExtensions.CreateLogger<QQAuthenticationMiddleware>(app);
            if (options.Provider == null)
            {
                options.Provider = new QQAuthenticationProvider();
            }

            if (this.Options.StateDataFormat == null)
            {
                this.Options.StateDataFormat =new PropertiesDataFormat(app.CreateDataProtector(typeof(QQAuthenticationMiddleware).FullName,this.Options.AuthenticationType,"v1"));
            }
            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType))
                this.Options.SignInAsAuthenticationType = AppBuilderSecurityExtensions.GetDefaultSignInAsAuthenticationType(app);


            this._httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options));
            
            this._httpClient.MaxResponseContentBufferSize = 10485760L;
        }

        protected override AuthenticationHandler<QQAuthenticationOptions> CreateHandler()
        {
            return new QQAuthenticationHandler(this._httpClient,this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(QQAuthenticationOptions options)
        {
            return new WebRequestHandler();
        }
    }
}