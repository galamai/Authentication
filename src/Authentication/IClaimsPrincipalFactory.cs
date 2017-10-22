using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface IClaimsPrincipalFactory
    {
        Task<ClaimsPrincipal> CreateAsync(ISignIn signIn);
    }
}
