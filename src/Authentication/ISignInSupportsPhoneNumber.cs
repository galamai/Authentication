using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public interface ISignInSupportsPhoneNumber
    {
        string PhoneNumber { get; }
        bool PhoneNumberConfirmed { get; }
    }
}
