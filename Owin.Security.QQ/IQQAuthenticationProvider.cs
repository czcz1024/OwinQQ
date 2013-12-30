namespace Owin.Security.QQ
{
    using System.Threading.Tasks;

    public interface IQQAuthenticationProvider
    {
        Task Authenticated(QQAuthenticatedContext context);
        
        Task ReturnEndpoint(QQReturnEndpointContext context);
    }
}