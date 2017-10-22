using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsEmail
    {
        string Email { get; }
        bool EmailConfirmed { get; }
    }
}
