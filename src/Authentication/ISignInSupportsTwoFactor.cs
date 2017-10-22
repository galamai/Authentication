using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsTwoFactor
    {
        bool RequireTwoFactorSignIn { get; }
    }
}
