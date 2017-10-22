using Microsoft.AspNetCore.Authentication.Cookies;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public interface ISecurityStampValidator
    {
        Task ValidateAsync(CookieValidatePrincipalContext context);
    }
}
