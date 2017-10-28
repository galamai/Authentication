using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public class SecurityStampValidator : ISecurityStampValidator
    {
        private readonly ISignInFactory _signInFactory;
        private readonly IClaimsPrincipalFactory _claimsPrincipalFactory;
        private readonly ISignInManager _signInManager;
        private readonly ISystemClock _clock;
        private readonly SignInManagerOptions _options;

        public SecurityStampValidator(
            ISignInFactory signInFactory,
            IClaimsPrincipalFactory claimsPrincipalFactory,
            ISignInManager signInManager,
            ISystemClock clock,
            IOptions<SignInManagerOptions> optionsAccessor)
        {
            _signInFactory = signInFactory;
            _claimsPrincipalFactory = claimsPrincipalFactory;
            _signInManager = signInManager;
            _clock = clock;
            _options = optionsAccessor.Value;
        }

        public static Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
        {
            if (context.HttpContext.RequestServices == null)
            {
                throw new InvalidOperationException("RequestServices is null.");
            }

            var validator = context.HttpContext.RequestServices.GetRequiredService<ISecurityStampValidator>();
            return validator.ValidateAsync(context);
        }

        public async Task ValidateAsync(CookieValidatePrincipalContext context)
        {
            var currentUtc = DateTimeOffset.UtcNow;
            if (context.Options != null && _clock != null)
            {
                currentUtc = _clock.UtcNow;
            }

            var issuedUtc = context.Properties.IssuedUtc;
            var validate = (issuedUtc == null);
            if (issuedUtc != null)
            {
                var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                validate = timeElapsed > _options.SecurityStampValidationInterval;
            }
            if (validate)
            {
                var signIn = await FindSignInWithValidSecurityStampAsync(context.Principal);
                if (signIn != null)
                {
                    var newPrincipal = await _claimsPrincipalFactory.CreateAsync(signIn);

                    if (_options.OnSecurityStampRefreshingPrincipal != null)
                    {
                        var replaceContext = new SecurityStampPrincipalContext
                        {
                            CurrentPrincipal = context.Principal,
                            NewPrincipal = newPrincipal
                        };

                        await _options.OnSecurityStampRefreshingPrincipal(replaceContext);
                        newPrincipal = replaceContext.NewPrincipal;
                    }
                }
                else
                {
                    context.RejectPrincipal();
                    await _signInManager.SignOutAsync();
                }
            }
        }

        private async Task<ISignIn> FindSignInWithValidSecurityStampAsync(ClaimsPrincipal principal)
        {
            var signIn = await _signInFactory.CreateAsync(principal);
            if (signIn != null && signIn is ISignInSupportsSecurityStamp supportsSecurityStamp)
            {
                var securityStamp = principal.FindFirstClaimValue(_options.ClaimsIdentityOptions.SecurityStampClaimType);
                if (securityStamp == supportsSecurityStamp.SecurityStamp)
                {
                    return signIn;
                }
            }

            return null;
        }
    }
}
