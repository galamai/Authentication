using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Authentication
{
    public class ExternalLoginInfo : SignInExternalLogin
    {
        public ClaimsPrincipal Principal { get; set; }
        public IEnumerable<AuthenticationToken> AuthenticationTokens { get; set; }
    }
}
