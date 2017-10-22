using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface ISignInManager
    {
        bool IsAuthenticated(ClaimsPrincipal claimsPrincipal);
        string GetUserId(ClaimsPrincipal claimsPrincipal);
        string GetUserName(ClaimsPrincipal claimsPrincipal);
        Task TwoFactorSignInAsync(string id, string loginProvider = null);
        Task<TwoFactorAuthenticationInfo> RetrieveTwoFactorInfoAsync();
        Task<bool> IsTwoFactorClientRememberedAsync(string id);
        Task ForgetTwoFactorClientAsync();
        Task<SignInResult> SignInAsync(ISignIn signIn, bool isPersistent, string authenticationMethod = null);
        Task<SignInResult> SignInByPasswordAsync(ISignIn signIn, string password, bool isPersistent);
        Task<SignInResult> SignInByTwoFactorTokenAsync(ISignIn signIn, string tokenProvider, string token, bool isPersistent, bool rememberClient);
        Task<SignInResult> ExternalSignInAsync(ISignIn signIn, string loginProvider, bool isPersistent);
        AuthenticationProperties ConfigureExternalAuthenticationProperties(string loginProvider, string redirectUrl, string id = null);
        Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null);
        Task SignOutAsync();
        Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync();
        Task RefreshSignInAsync(ISignIn signIn);
    }
}
