using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication
{
    public class SignInExternalLogin
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
        public string ProviderDisplayName { get; set; }
    }
}
