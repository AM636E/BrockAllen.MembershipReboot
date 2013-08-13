﻿/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;

namespace BrockAllen.MembershipReboot
{
    public abstract class CookieBasedTwoFactorAuthPolicy :
        ITwoFactorAuthenticationPolicy,
        IEventHandler<SuccessfulTwoFactorAuthCodeLoginEvent>
    {
        const string CookieBasedTwoFactorAuthPolicyCookieName = "mr.cbtfap";

        protected abstract bool HasCookie(string name, string value);
        protected abstract void IssueCookie(string name, string value);

        string GetCookieValue(UserAccount account)
        {
            return CryptoHelper.Hash(account.ID.ToString(), account.HashedPassword);
        }

        public bool RequestRequiresTwoFactorAuth(UserAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            if (HasCookie(CookieBasedTwoFactorAuthPolicyCookieName, GetCookieValue(account)))
            {
                return false;
            }

            return true;
        }

        public void Handle(SuccessfulTwoFactorAuthCodeLoginEvent evt)
        {
            if (evt == null) throw new ArgumentNullException("evt");

            IssueCookie(CookieBasedTwoFactorAuthPolicyCookieName, GetCookieValue(evt.Account));
        }
    }
}
