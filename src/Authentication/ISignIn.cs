using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignIn
    {
        string Id { get; }
        string Name { get; }
    }
}
