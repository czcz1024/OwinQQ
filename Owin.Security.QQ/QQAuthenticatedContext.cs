namespace Owin.Security.QQ
{
    using System;
    using System.Net.Http;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    using Microsoft.Owin;
    using Microsoft.Owin.Security.Provider;

    public class QQAuthenticatedContext : BaseContext
    {
        public string AccessToken { get;private set; }

        public TimeSpan? ExpiresIn { get; private set; }

        public string OpenId { get; private set; }

        public string Name { get; private set; }

        public QQAuthenticatedContext(IOwinContext context,string accessToken,string openid,string name)
            : base(context)
        {
            this.OpenId = openid;
            this.AccessToken = accessToken;
            this.Name = name;


        }
    }
}