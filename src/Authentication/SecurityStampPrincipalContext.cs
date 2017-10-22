using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Authentication
{
    public class SecurityStampPrincipalContext
    {
        public ClaimsPrincipal CurrentPrincipal { get; set; }
        public ClaimsPrincipal NewPrincipal { get; set; }
    }
}
