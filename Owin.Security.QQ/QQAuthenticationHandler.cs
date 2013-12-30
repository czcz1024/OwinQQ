namespace Owin.Security.QQ
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    internal class QQAuthenticationHandler : AuthenticationHandler<QQAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public QQAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            bool flag;
            if (!string.IsNullOrEmpty(this.Options.CallbackPath) && this.Options.CallbackPath == this.Request.Path.ToString())
                flag = await this.InvokeReturnPathAsync();
            else
                flag = false;
            return flag;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await this.AuthenticateAsync();
            bool flag;
            if (model == null)
            {
                this.Response.StatusCode = 500;
                flag = true;
            }
            else
            {
                QQReturnEndpointContext context = new QQReturnEndpointContext(this.Context, model);
                context.SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType;
                context.RedirectUri = model.Properties.RedirectUri;
                model.Properties.RedirectUri = null;

                await this.Options.Provider.ReturnEndpoint(context);
                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity claimsIdentity = context.Identity;
                    if (!string.Equals(claimsIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                        claimsIdentity = new ClaimsIdentity(claimsIdentity.Claims, context.SignInAsAuthenticationType, claimsIdentity.NameClaimType, claimsIdentity.RoleClaimType);
                    this.Context.Authentication.SignIn(context.Properties, new ClaimsIdentity[1]
                                                                               {
                                                                                   claimsIdentity
                                                                               });
                }
                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    if (context.Identity == null)
                        context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                    this.Response.Redirect(context.RedirectUri);
                    context.RequestCompleted();
                }
                flag = context.IsRequestCompleted;
            }


            return flag;
        }

        private static string GetStateParameter(IReadableStringCollection query)
        {
            IList<string> values = query.GetValues("state");
            if (values != null && values.Count == 1)
                return values[0];
            else
                return null;
        }
        private AuthenticationProperties UnpackStateParameter(IReadableStringCollection query)
        {
            string stateParameter = GetStateParameter(query);
            if (stateParameter != null)
                return this.Options.StateDataFormat.Unprotect(stateParameter);
            else
                return null;
        }
        
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            AuthenticationTicket authenticationTicket;

            IReadableStringCollection query = this.Request.Query;
            properties = this.UnpackStateParameter(query);
            string code=string.Empty;
            IList<string> values = query.GetValues("code");
            if (values != null && values.Count == 1)
                code = values[0];
            if (string.IsNullOrEmpty(code))
            {
                authenticationTicket = new AuthenticationTicket(null, properties);
                return authenticationTicket;
            }

            if (properties == null)
            {
                authenticationTicket = null;
            }
            else if (!this.ValidateCorrelationId(properties, this._logger))
            {
                authenticationTicket = new AuthenticationTicket(null, properties);
            }
            else
            {
                string tokenEndpoint = "https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id={0}&client_secret={1}&code={2}&redirect_uri={3}";
                var url = string.Format(
                    tokenEndpoint,
                    Uri.EscapeDataString(this.Options.ApiID),
                    Uri.EscapeDataString(this.Options.ApiKey),
                    Uri.EscapeDataString(code), Uri.EscapeDataString("http://"+this.Request.Host));
                HttpResponseMessage tokenResponse = await this._httpClient.GetAsync(url, this.Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string access_tokenReturnValue = await tokenResponse.Content.ReadAsStringAsync();
                var pa = @"access_token=(.+?)\&";
                string accesstoken = Regex.Match(access_tokenReturnValue, pa).Groups[1].Value;

                var meurltemp = "https://graph.qq.com/oauth2.0/me?access_token={0}";
                var meurl = string.Format(meurltemp, Uri.EscapeDataString(accesstoken));
                var meResponse = await this._httpClient.GetAsync(meurl,this.Request.CallCancelled);
                meResponse.EnsureSuccessStatusCode();
                var me = await meResponse.Content.ReadAsStringAsync();

                //上面获取到open id，再通过 open id获取到昵称
                var paopenid = "\"openid\":\"(.+?)\"";
                var openid = Regex.Match(me, paopenid).Groups[1].Value;
                var nameurltemp = "https://graph.qq.com/user/get_user_info?access_token={0}&oauth_consumer_key={1}&openid={2}";
                var nameurl = string.Format(
                    nameurltemp,
                    Uri.EscapeDataString(accesstoken),
                    Uri.EscapeDataString(this.Options.ApiID),
                    Uri.EscapeDataString(openid));
                var nameResponse = await this._httpClient.GetAsync(nameurl, this.Request.CallCancelled);
                nameResponse.EnsureSuccessStatusCode();
                var nametxt=await nameResponse.Content.ReadAsStringAsync();
                var paname = "\"nickname\": \"(.+?)\"";
                var name = Regex.Match(nametxt, paname).Groups[1].Value;

                var context = new QQAuthenticatedContext(this.Context,accesstoken,openid,name);

                var identity = new ClaimsIdentity(this.Options.AuthenticationType);

                if (!string.IsNullOrEmpty(context.OpenId))
                {
                    identity.AddClaim(
                        new Claim(
                            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                            context.OpenId,
                            "http://www.w3.org/2001/XMLSchema#string",
                            this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    identity.AddClaim(
                        new Claim(
                            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                            context.Name,
                            "http://www.w3.org/2001/XMLSchema#string",
                            this.Options.AuthenticationType));
                }
                await this.Options.Provider.Authenticated(context);
                authenticationTicket = new AuthenticationTicket(identity, properties);
            }
            
            return authenticationTicket;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
                return Task.FromResult((object)null);
            AuthenticationResponseChallenge responseChallenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);
            if (responseChallenge != null)
            {
                string stringToEscape = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host;
                AuthenticationProperties properties = responseChallenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                    properties.RedirectUri =
                        string.Concat(
                            new object[]
                                {
                                    stringToEscape, this.Request.PathBase, this.Request.Path,
                                    this.Request.QueryString
                                });
                this.GenerateCorrelationId(properties);

                var loginRedirectUrlFormat = "https://graph.qq.com/oauth2.0/authorize?client_id={0}&response_type=code&redirect_uri={1}";
                var protector=this.Options.StateDataFormat.Protect(properties);
                var url = string.Format(
                    loginRedirectUrlFormat,
                    Uri.EscapeDataString(this.Options.ApiID),
                    Uri.EscapeDataString(BuildReturnTo(protector)));
                this.Response.StatusCode = 302;
                this.Response.Headers.Set("Location", url);
            }
            return base.ApplyResponseChallengeAsync();
        }

        private string BuildReturnTo(string state)
        {
            return this.Request.Scheme + "://" + this.Request.Host + this.RequestPathBase + this.Options.CallbackPath + "?state=" + Uri.EscapeDataString(state);
        }
    }
}