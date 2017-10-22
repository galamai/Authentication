using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Authentication
{
    public class SignInManagerOptions
    {
        public ClaimsIdentityOptions ClaimsIdentityOptions { get; set; } = new ClaimsIdentityOptions();
        public bool AllowRememberLogin { get; set; } = true;
        public TimeSpan RememberLoginDuration { get; set; } = TimeSpan.FromDays(14);
        public TimeSpan SecurityStampValidationInterval { get; set; } = TimeSpan.FromMinutes(30);
        public Func<SecurityStampPrincipalContext, Task> OnSecurityStampRefreshingPrincipal { get; set; }
    }
}
