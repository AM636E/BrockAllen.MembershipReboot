/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BrockAllen.MembershipReboot
{
    public class AggregateValidator<TAccount> : Dictionary<string, IValidator<TAccount>>, IValidator<TAccount>
        where TAccount : UserAccount
    {
        public ValidationResult Validate(UserAccountService<TAccount> service, TAccount account, string value)
        {
            if (service == null) throw new ArgumentNullException(nameof(service));
            if (account == null) throw new ArgumentNullException(nameof(account));

            foreach (var item in this)
            {
                var result = item.Value.Validate(service, account, value);
                if (result != null && result != ValidationResult.Success)
                {
                    return result;
                }
            }
            return null;
        }
    }
}
