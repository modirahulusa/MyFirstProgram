using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using BajajDataLayer;
using System.Web.Http.Filters;
using System.Web.Http.Controllers;
using System.Net.Http;
using System.Net;
using System.Text;
using System.Threading;
using System.Security.Principal;

namespace BajajWebAPI
{
    public class BajajSecurity
    {
        public static bool Login(string userName, string password)
        {
            using (BAJAJEntities ObjSecurity = new BAJAJEntities())
            {
                return ObjSecurity.T_MS_USER.Any(user => user.USER_NAME == userName && user.USER_PASSWORD == password);
            }
        }
    }

    public class BasicAuthenticationAttribute : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
            else
            {
                AIRS.bizBarcode.bzBarcode Obj = new AIRS.bizBarcode.bzBarcode();
                string AuthenticationToken = actionContext.Request.Headers.Authorization.Parameter;
                string DAuToken = Encoding.UTF8.GetString(Convert.FromBase64String(AuthenticationToken));
                string UserName = DAuToken.Split(':')[0];
                string PassWord = DAuToken.Split(':')[1];
                if (BajajSecurity.Login(UserName, Obj.Encrypt(PassWord, "1604")))
                {
                    Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity(UserName),null);

                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
            }
        }
    }
}