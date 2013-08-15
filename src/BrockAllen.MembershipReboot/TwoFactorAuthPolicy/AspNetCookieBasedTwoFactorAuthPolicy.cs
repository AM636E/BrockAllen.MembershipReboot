﻿/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Linq;
using System.Web;

namespace BrockAllen.MembershipReboot
{
    public class AspNetCookieBasedTwoFactorAuthPolicy : CookieBasedTwoFactorAuthPolicy
    {
        int persistentCookieDays;
        public AspNetCookieBasedTwoFactorAuthPolicy()
            : this(MembershipRebootConstants.AuthenticationService.DefaultPersistentCookieDays)
        {
        }

        public AspNetCookieBasedTwoFactorAuthPolicy(int persistentCookieDays)
        {
            this.persistentCookieDays = persistentCookieDays;
        }

        protected override bool HasCookie(string name, string value)
        {
            var ctx = HttpContext.Current;
            if (ctx.Request.Cookies.AllKeys.Contains(name))
            {
                return ctx.Request.Cookies[name].Value == value;
            }
            return false;
        }

        protected override void IssueCookie(string name, string value)
        {
            var ctx = HttpContext.Current;
            if (ctx.Request.IsSecureConnection)
            {
                var cookie = new HttpCookie(name, value);
                cookie.HttpOnly = true;
                cookie.Secure = true;
                cookie.Expires = DateTime.Now.AddDays(this.persistentCookieDays);
                cookie.Shareable = false;
                cookie.Path = ctx.Request.ApplicationPath;
                if (!cookie.Path.EndsWith("/")) cookie.Path += "/";

                ctx.Response.Cookies.Add(cookie);
            }
        }
    }
}
