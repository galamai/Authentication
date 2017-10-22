using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsClaims
    {
        IEnumerable<SignInClaim> Claims { get; }
    }
}
