using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Authentication
{
    public static class PrincipalExtensions
    {
        public static string FindFirstClaimValue(this ClaimsPrincipal principal, string claimType)
        {
            return principal?.FindFirst(claimType)?.Value;
        }
    }
}
