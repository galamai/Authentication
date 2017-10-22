using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsSecurityStamp
    {
        string SecurityStamp { get; }
    }
}
