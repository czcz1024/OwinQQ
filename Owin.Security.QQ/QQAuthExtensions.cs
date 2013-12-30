namespace Owin
{
    using System;

    using Owin.Security.QQ;

    public static class QQAuthExtensions
    {
        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, QQAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");
            app.Use(typeof(QQAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, string appId,string appKey)
        {
            return app.UseQQAuthentication(new QQAuthenticationOptions { 
                AppID=appId,
                AppKey=appKey,
            });
        }
    }
}