using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace Authentication
{
    public class ClaimsIdentityOptions
    {
        public string NameClaimType { get; set; } = ClaimTypes.Name;
        public string IdClaimType { get; set; } = ClaimTypes.NameIdentifier;
        public string RoleClaimType { get; set; } = ClaimTypes.Role;
        public string AuthenticationMethodClaimType { get; set; } = ClaimTypes.AuthenticationMethod;
        public string SecurityStampClaimType { get; set; } = "Identity.SecurityStamp";
    }
}
