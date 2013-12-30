namespace Owin.Security.Weibo
{
    using System;

    public static class SinaAuthExtensions
    {
        public static IAppBuilder UseSinaAuthentication(this IAppBuilder app, SinaAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");
            app.Use(typeof(SinaAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseSinaAuthentication(this IAppBuilder app, string appId, string appKey)
        {
            return app.UseSinaAuthentication(new SinaAuthenticationOptions
            {
                AppID = appId,
                AppKey = appKey,
            });
        } 
    }
}