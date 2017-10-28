using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public class SignInManager : ISignInManager
    {
        private const string LoginProviderKey = "LoginProvider";
        private const string XsrfKey = "XsrfId";

        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IClaimsPrincipalFactory _claimsPrincipalFactory;
        private readonly ITokenProviderManager _tokenProviderManager;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly SignInManagerOptions _options;

        public SignInManager(
            IHttpContextAccessor contextAccessor,
            IPasswordHasher passwordHasher,
            IClaimsPrincipalFactory claimsPrincipalFactory,
            ITokenProviderManager tokenProviderManager,
            IAuthenticationSchemeProvider authenticationSchemeProvider,
            IOptions<SignInManagerOptions> optionsAccessor)
        {
            _contextAccessor = contextAccessor;
            _passwordHasher = passwordHasher;
            _claimsPrincipalFactory = claimsPrincipalFactory;
            _tokenProviderManager = tokenProviderManager;
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _options = optionsAccessor.Value;
        }

        public bool IsAuthenticated(ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal?.Identities != null &&
                claimsPrincipal.Identities.Any(x => x.AuthenticationType == SignInConstants.ApplicationScheme);

        }

        public async Task TwoFactorSignInAsync(string id, string loginProvider = null)
        {
            var claimsPrincipal = CreateTwoFactorClaimsPrincipal(id, loginProvider);
            await _contextAccessor.HttpContext.SignInAsync(SignInConstants.TwoFactorUserIdScheme, claimsPrincipal);
        }

        public async Task<TwoFactorAuthenticationInfo> RetrieveTwoFactorInfoAsync()
        {
            var result = await _contextAccessor.HttpContext.AuthenticateAsync(SignInConstants.TwoFactorUserIdScheme);
            if (result?.Principal != null)
            {
                return new TwoFactorAuthenticationInfo()
                {
                    UserId = result.Principal.FindFirstClaimValue(ClaimTypes.Name),
                    LoginProvider = result.Principal.FindFirstClaimValue(ClaimTypes.AuthenticationMethod)
                };
            }

            return null;
        }

        public async Task<bool> IsTwoFactorClientRememberedAsync(string id)
        {
            var result = await _contextAccessor.HttpContext.AuthenticateAsync(SignInConstants.TwoFactorRememberMeScheme);
            return (result?.Principal != null && result.Principal.FindFirstClaimValue(_options.ClaimsIdentityOptions.IdClaimType) == id);
        }

        public Task ForgetTwoFactorClientAsync()
        {
            return _contextAccessor.HttpContext.SignOutAsync(SignInConstants.TwoFactorRememberMeScheme);
        }

        public Task<SignInResult> SignInAsync(ISignIn signIn, bool isPersistent, string authenticationMethod = null)
        {
            AuthenticationProperties props = null;

            if (_options.AllowRememberLogin && isPersistent)
            {
                props = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow + _options.RememberLoginDuration,
                };
            };

            return SignInAsync(signIn, isPersistent, props, authenticationMethod);
        }

        public async Task<SignInResult> SignInByPasswordAsync(ISignIn signIn, string password, bool isPersistent)
        {
            if (IsLocked(signIn))
            {
                return SignInResult.LockedOut;
            }

            if (signIn is ISignInSupportsPassword supportsPassword &&
                supportsPassword.PasswordHash != null &&
                _passwordHasher.VerifyPassword(password, supportsPassword.PasswordHash))
            {
                if (await TwoFactorSignInAsync(signIn))
                {
                    return SignInResult.TwoFactorSuccess;
                }

                return await SignInAsync(signIn, isPersistent);
            }

            return SignInResult.Failed;
        }

        public async Task<SignInResult> SignInByTwoFactorTokenAsync(ISignIn signIn, string tokenProvider, string token, bool isPersistent, bool rememberClient)
        {
            if (IsLocked(signIn))
            {
                return SignInResult.LockedOut;
            }

            var tp = _tokenProviderManager.FindTokenProvider(tokenProvider);
            if (tp != null && tp.Validate(Purpose.TwoFactor, token, signIn))
            {
                if (rememberClient)
                {
                    await RememberTwoFactorClientAsync(signIn.Id);
                }

                await _contextAccessor.HttpContext.SignOutAsync(SignInConstants.TwoFactorUserIdScheme);
                return await SignInAsync(signIn, isPersistent, tokenProvider);
            }

            return SignInResult.Failed;
        }

        public async Task<SignInResult> ExternalSignInAsync(ISignIn signIn, string loginProvider, bool isPersistent)
        {
            await _contextAccessor.HttpContext.SignOutAsync(SignInConstants.ExternalScheme);

            if (IsLocked(signIn))
            {
                return SignInResult.LockedOut;
            }

            if (await TwoFactorSignInAsync(signIn))
            {
                return SignInResult.TwoFactorSuccess;
            }

            return await SignInAsync(signIn, isPersistent, loginProvider);
        }

        public AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUrl, string id = null)
        {
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items[LoginProviderKey] = provider;
            if (id != null)
            {
                properties.Items[XsrfKey] = id;
            }
            return properties;
        }

        public async Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null)
        {
            var auth = await _contextAccessor.HttpContext.AuthenticateAsync(SignInConstants.ExternalScheme);
            var items = auth?.Properties?.Items;
            if (auth?.Principal == null || items == null || !items.ContainsKey(LoginProviderKey))
            {
                return null;
            }

            if (expectedXsrf != null)
            {
                if (!items.ContainsKey(XsrfKey))
                {
                    return null;
                }
                var id = items[XsrfKey];
                if (id != expectedXsrf)
                {
                    return null;
                }
            }

            var providerKey = auth.Principal.FindFirstClaimValue(ClaimTypes.NameIdentifier);
            var provider = items[LoginProviderKey];
            if (providerKey == null || provider == null)
            {
                return null;
            }

            return new ExternalLoginInfo()
            {
                Principal = auth.Principal,
                LoginProvider = provider,
                ProviderKey = providerKey,
                ProviderDisplayName = provider,
                AuthenticationTokens = new AuthenticationProperties(items).GetTokens()
            };
        }

        public virtual Task SignOutAsync()
        {
            return Task.WhenAll(
                _contextAccessor.HttpContext.SignOutAsync(SignInConstants.ApplicationScheme),
                _contextAccessor.HttpContext.SignOutAsync(SignInConstants.ExternalScheme),
                _contextAccessor.HttpContext.SignOutAsync(SignInConstants.TwoFactorUserIdScheme));
        }

        private async Task<bool> TwoFactorSignInAsync(ISignIn signIn)
        {
            if (signIn is ISignInSupportsTwoFactor supportsTwoFactor &&
                    supportsTwoFactor.RequireTwoFactorSignIn &&
                    !await IsTwoFactorClientRememberedAsync(signIn.Id))
            {
                await TwoFactorSignInAsync(signIn.Id);
                return true;
            }

            return false;
        }

        private bool IsLocked(ISignIn signIn)
        {
            if (signIn is ISignInSupportsLockout signInSupportedLockout && signInSupportedLockout.LockoutEnd > DateTimeOffset.UtcNow)
            {
                return true;
            }
            return false;
        }

        private async Task<SignInResult> SignInAsync(ISignIn signIn, bool isPersistent, AuthenticationProperties properties, string authenticationMethod = null)
        {
            var userPrincipal = await _claimsPrincipalFactory.CreateAsync(signIn);
            if (authenticationMethod != null)
            {
                userPrincipal.Identities.First().AddClaim(new Claim(_options.ClaimsIdentityOptions.AuthenticationMethodClaimType, authenticationMethod));
            }

            await _contextAccessor.HttpContext.SignInAsync(
                    SignInConstants.ApplicationScheme,
                    userPrincipal,
                    properties ?? new AuthenticationProperties());

            return SignInResult.Success;
        }



        private Task RememberTwoFactorClientAsync(string id)
        {
            var rememberBrowserIdentity = new ClaimsIdentity(SignInConstants.TwoFactorRememberMeScheme);
            rememberBrowserIdentity.AddClaim(new Claim(_options.ClaimsIdentityOptions.IdClaimType, id));
            return _contextAccessor.HttpContext.SignInAsync(
                SignInConstants.TwoFactorRememberMeScheme,
                new ClaimsPrincipal(rememberBrowserIdentity),
                new AuthenticationProperties { IsPersistent = true });
        }

        private ClaimsPrincipal CreateTwoFactorClaimsPrincipal(string id, string loginProvider = null)
        {
            var identity = new ClaimsIdentity(SignInConstants.TwoFactorUserIdScheme);
            identity.AddClaim(new Claim(_options.ClaimsIdentityOptions.IdClaimType, id));
            if (loginProvider != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
            }
            return new ClaimsPrincipal(identity);
        }

        public async Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()
        {
            var schemes = await _authenticationSchemeProvider.GetAllSchemesAsync();
            return schemes.Where(s => !string.IsNullOrEmpty(s.DisplayName));
        }

        public async Task RefreshSignInAsync(ISignIn signIn)
        {
            var auth = await _contextAccessor.HttpContext.AuthenticateAsync(SignInConstants.ApplicationScheme);
            var authenticationMethod = auth?.Principal?.FindFirstClaimValue(ClaimTypes.AuthenticationMethod);
            await SignInAsync(signIn, auth?.Properties.IsPersistent ?? false, auth?.Properties, authenticationMethod);
        }

        public string GetUserId(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
                throw new ArgumentNullException(nameof(claimsPrincipal));

            return claimsPrincipal.FindFirstClaimValue(_options.ClaimsIdentityOptions.IdClaimType);
        }

        public string GetUserName(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
                throw new ArgumentNullException(nameof(claimsPrincipal));

            return claimsPrincipal.FindFirstClaimValue(_options.ClaimsIdentityOptions.NameClaimType);
        }
    }
}
