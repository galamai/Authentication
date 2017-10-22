using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsRoles
    {
        IEnumerable<string> Roles { get; }
    }
}
