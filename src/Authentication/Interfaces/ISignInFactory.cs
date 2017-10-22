using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Interfaces
{
    public interface ISignInFactory
    {
        Task<ISignIn> CreateAsync(ClaimsPrincipal claimsPrincipal);
    }
}
