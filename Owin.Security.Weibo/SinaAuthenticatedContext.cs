namespace Owin.Security.Weibo
{
    using System;

    using Microsoft.Owin;
    using Microsoft.Owin.Security.Provider;

    public class SinaAuthenticatedContext : BaseContext
    {
        public string AccessToken { get; private set; }

        public TimeSpan? ExpiresIn { get; private set; }

        public string OpenId { get; private set; }

        public string Name { get; private set; }
        public SinaAuthenticatedContext(IOwinContext context,string accessToken,string openid,string name)
            : base(context)
        {
            this.OpenId = openid;
            this.AccessToken = accessToken;
            this.Name = name;
        }
    }
}