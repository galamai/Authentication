using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsExternalLogins
    {
        IEnumerable<SignInExternalLogin> Logins { get; }
    }
}
