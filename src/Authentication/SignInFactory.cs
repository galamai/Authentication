using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public class SignInFactory : ISignInFactory
    {
        private readonly ISignInManager _signInManager;

        public SignInFactory(ISignInManager signInManager)
        {
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        }

        public Task<ISignIn> CreateAsync(ClaimsPrincipal claimsPrincipal)
        {
            var id = _signInManager.GetUserId(claimsPrincipal);
            if (id != null)
            {
                var name = _signInManager.GetUserName(claimsPrincipal);
                return Task.FromResult<ISignIn>(new SignIn(id, name));
            }

            return Task.FromResult<ISignIn>(null);
        }
    }
}
