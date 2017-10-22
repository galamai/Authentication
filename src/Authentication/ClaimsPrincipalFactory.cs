using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public class ClaimsPrincipalFactory : IClaimsPrincipalFactory
    {
        private readonly SignInManagerOptions _options;

        public ClaimsPrincipalFactory(IOptions<SignInManagerOptions> optionsAccessor)
        {
            _options = optionsAccessor.Value;
        }

        public virtual Task<ClaimsPrincipal> CreateAsync(ISignIn signIn)
        {
            var claimsIdentity = new ClaimsIdentity(SignInConstants.ApplicationScheme,
                _options.ClaimsIdentityOptions.NameClaimType,
                _options.ClaimsIdentityOptions.RoleClaimType);
            claimsIdentity.AddClaim(new Claim(_options.ClaimsIdentityOptions.IdClaimType, signIn.Id));
            claimsIdentity.AddClaim(new Claim(_options.ClaimsIdentityOptions.NameClaimType, signIn.Name));
            if (signIn is ISignInSupportsSecurityStamp supportsSecurityStamp && supportsSecurityStamp.SecurityStamp != null)
            {
                claimsIdentity.AddClaim(new Claim(_options.ClaimsIdentityOptions.SecurityStampClaimType,
                    supportsSecurityStamp.SecurityStamp));
            }
            if (signIn is ISignInSupportsRoles supportsRoles)
            {
                claimsIdentity.AddClaims(supportsRoles.Roles.Select(x => new Claim(_options.ClaimsIdentityOptions.RoleClaimType, x)));
            }
            if (signIn is ISignInSupportsClaims supportsClaims)
            {
                claimsIdentity.AddClaims(supportsClaims.Claims.Select(x => new Claim(x.Type, x.Value)));
            }

            return Task.FromResult(new ClaimsPrincipal(claimsIdentity));
        }
    }
}
