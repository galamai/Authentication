using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class TwoFactorAuthenticationInfo
    {
        public string UserId { get; set; }
        public string LoginProvider { get; set; }
    }
}
