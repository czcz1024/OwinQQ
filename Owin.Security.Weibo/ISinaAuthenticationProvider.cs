namespace Owin.Security.Weibo
{
    using System.Threading.Tasks;

    public interface ISinaAuthenticationProvider
    {
        Task Authenticated(SinaAuthenticatedContext context);

        Task ReturnEndpoint(SinaReturnEndpointContext context);
    }
}