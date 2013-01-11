﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Helpers;

namespace BrockAllen.MembershipReboot
{
    public class UserAccount
    {
        const string ChangeEmailVerificationPrefix = "changeEmail";
        
        internal static UserAccount Create(string tenant, string username, string password, string email)
        {
            UserAccount account = new UserAccount
            {
                Tenant = tenant,
                Username = username,
                Email = email,
                Created = DateTime.UtcNow,
                IsAccountVerified = !SecuritySettings.Instance.RequireAccountVerification,
                IsLoginAllowed = SecuritySettings.Instance.AllowLoginAfterAccountCreation,
                Claims = new List<UserClaim>()
            };

            account.SetPassword(password);
            if (SecuritySettings.Instance.RequireAccountVerification)
            {
                account.VerificationKey = StripUglyBase64(Crypto.GenerateSalt());
                account.VerificationKeySent = DateTime.UtcNow;
            }

            return account;
        }

        [Key]
        public int ID { get; set; }

        [StringLength(50)]
        [Required]
        public virtual string Tenant { get; private set; }
        [StringLength(100)]
        [Required]
        public virtual string Username { get; private set; }
        [EmailAddress]
        [StringLength(100)]
        [Required]
        public virtual string Email { get; private set; }

        public virtual DateTime Created { get; private set; }
        public virtual DateTime PasswordChanged { get; private set; }

        public virtual bool IsAccountVerified { get; private set; }
        public virtual bool IsLoginAllowed { get; set; }
        public virtual bool IsAccountClosed { get; internal set; }

        public virtual DateTime? LastLogin { get; private set; }
        public virtual DateTime? LastFailedLogin { get; private set; }
        public virtual int FailedLoginCount { get; private set; }

        [StringLength(50)]
        public virtual string VerificationKey { get; private set; }
        public virtual DateTime? VerificationKeySent { get; private set; }

        [Required]
        [StringLength(200)]
        public virtual string HashedPassword { get; private set; }

        public virtual ICollection<UserClaim> Claims { get; private set; }

        internal bool VerifyAccount(string key)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                Tracing.Verbose("[UserAccount.VerifyAccount] failed -- no key");
                return false;
            }
            if (IsAccountVerified)
            {
                Tracing.Verbose("[UserAccount.VerifyAccount] failed -- account already verified");
                return false;
            }
            if (this.VerificationKey != key)
            {
                Tracing.Verbose("[UserAccount.VerifyAccount] failed -- verification key doesn't match");
                return false;
            }

            this.IsAccountVerified = true;
            this.VerificationKey = null;
            this.VerificationKeySent = null;

            return true;
        }

        internal bool ChangePassword(string oldPassword, string newPassword, int failedLoginCount, TimeSpan lockoutDuration)
        {
            if (Authenticate(oldPassword, failedLoginCount, lockoutDuration))
            {
                SetPassword(newPassword);
                return true;
            }

            Tracing.Verbose("[UserAccount.ChangePassword] failed -- auth failed");

            return false;
        }

        internal void SetPassword(string password)
        {
            if (String.IsNullOrWhiteSpace(password))
            {
                Tracing.Verbose("[UserAccount.SetPassword] failed -- no password provided");
                
                throw new ValidationException("Invalid password");
            }

            Tracing.Verbose("[UserAccount.SetPassword] setting new password hash");

            HashedPassword = Crypto.HashPassword(password);
            PasswordChanged = DateTime.UtcNow;
        }

        bool IsVerificationKeyStale()
        {
            return this.VerificationKeySent < DateTime.UtcNow.AddDays(-1);
        }

        internal virtual bool ResetPassword()
        {
            // if they've not yet verified then don't allow changes
            if (!this.IsAccountVerified)
            {
                Tracing.Verbose("[UserAccount.ResetPassword] failed -- account not verified");

                return false;
            }

            // if there's no current key, or if there is a key but 
            // it's older than one day, create a new reset key
            if (this.VerificationKey == null || IsVerificationKeyStale())
            {
                Tracing.Verbose("[UserAccount.ResetPassword] creating new verification keys");

                this.VerificationKey = StripUglyBase64(Crypto.GenerateSalt());
                this.VerificationKeySent = DateTime.UtcNow;
            }
            else
            {
                Tracing.Verbose("[UserAccount.ResetPassword] not creating new verification keys");
            }

            return true;
        }

        internal virtual bool ChangePasswordFromResetKey(string key, string newPassword)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                Tracing.Verbose("[UserAccount.ChangePasswordFromResetKey] failed -- no key");
                return false;
            }

            if (!this.IsAccountVerified)
            {
                Tracing.Verbose("[UserAccount.ChangePasswordFromResetKey] failed -- account not verified");
                return false;
            }

            // if the key is too old don't honor it
            if (IsVerificationKeyStale())
            {
                Tracing.Verbose("[UserAccount.ChangePasswordFromResetKey] failed -- verification key too old");
                return false;
            }

            // check if key matches
            if (this.VerificationKey != key)
            {
                Tracing.Verbose("[UserAccount.ChangePasswordFromResetKey] failed -- verification keys don't match");
                return false;
            }

            this.VerificationKey = null;
            this.VerificationKeySent = null;
            this.SetPassword(newPassword);

            return true;
        }

        internal bool Authenticate(string password, int failedLoginCount, TimeSpan lockoutDuration)
        {
            if (failedLoginCount <= 0) throw new ArgumentException("failedLoginCount");

            if (String.IsNullOrWhiteSpace(password))
            {
                Tracing.Verbose("[UserAccount.Authenticate] failed -- no password");
                return false;
            }

            if (!IsAccountVerified)
            {
                Tracing.Verbose("[UserAccount.Authenticate] failed -- account not verified");
                return false;
            }
            if (!IsLoginAllowed)
            {
                Tracing.Verbose("[UserAccount.Authenticate] failed -- account not allowed to login");
                return false;
            }

            if (failedLoginCount <= FailedLoginCount &&
                LastFailedLogin <= DateTime.UtcNow.Add(lockoutDuration))
            {
                Tracing.Verbose("[UserAccount.Authenticate] failed -- account in lockout due to failed login attempts");
                
                FailedLoginCount++;
                return false;
            }

            var valid = Crypto.VerifyHashedPassword(HashedPassword, password);
            if (valid)
            {
                Tracing.Verbose("[UserAccount.Authenticate] authentication success");

                LastLogin = DateTime.UtcNow;
                FailedLoginCount = 0;
            }
            else
            {
                Tracing.Verbose("[UserAccount.Authenticate] failed -- invalid password");

                LastFailedLogin = DateTime.UtcNow;
                if (FailedLoginCount > 0) FailedLoginCount++;
                else FailedLoginCount = 1;
            }

            return valid;
        }

        internal bool ChangeEmailRequest(string newEmail)
        {
            if (String.IsNullOrWhiteSpace(newEmail)) throw new ValidationException("Invalid email.");

            // if they've not yet verified then fail
            if (!this.IsAccountVerified)
            {
                Tracing.Verbose("[UserAccount.ChangeEmailRequest] failed -- account not verified");
                return false;
            }

            var lowerEmail = newEmail.ToLower(new System.Globalization.CultureInfo("tr-TR", false));
            var emailHash = StripUglyBase64(Crypto.Hash(ChangeEmailVerificationPrefix + lowerEmail));

            // if there's no current key, or it's not a change email key
            // or if there is a key but it's older than one day, then create 
            // a new reset key
            if (this.VerificationKey == null ||
                !this.VerificationKey.StartsWith(emailHash) ||
                IsVerificationKeyStale())
            {
                Tracing.Verbose("[UserAccount.ChangeEmailRequest] creating a new reset key");

                var random = StripUglyBase64(Crypto.GenerateSalt());
                this.VerificationKey = emailHash + random;
                this.VerificationKeySent = DateTime.UtcNow;
            }
            else
            {
                Tracing.Verbose("[UserAccount.ChangeEmailRequest] not creating a new reset key");
            }

            return true;
        }

        internal bool ChangeEmailFromKey(string key, string newEmail)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                Tracing.Verbose("[UserAccount.ChangeEmailFromKey] failed -- no key");
                return false;
            }
            if (String.IsNullOrWhiteSpace(newEmail)) throw new ValidationException("Invalid email.");

            // only honor resets within the past day
            if (!IsVerificationKeyStale())
            {
                if (key == this.VerificationKey)
                {
                    var lowerEmail = newEmail.ToLower(new System.Globalization.CultureInfo("tr-TR", false));
                    var emailHash = StripUglyBase64(Crypto.Hash(ChangeEmailVerificationPrefix + lowerEmail));
                    if (this.VerificationKey.StartsWith(emailHash))
                    {
                        this.Email = newEmail;
                        this.VerificationKey = null;
                        this.VerificationKeySent = null;

                        return true;
                    }
                    else
                    {
                        Tracing.Verbose("[UserAccount.ChangeEmailFromKey] failed -- verification key is not marked as a email change verificaiton key");
                    }
                }
                else
                {
                    Tracing.Verbose("[UserAccount.ChangeEmailFromKey] failed -- verification keys don't match");
                }
            }
            else
            {
                Tracing.Verbose("[UserAccount.ChangeEmailFromKey] failed -- verification key is stale");
            }

            return false;
        }

        public bool HasClaim(string type)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");

            return this.Claims.Any(x => x.Type == type);
        }

        public bool HasClaim(string type, string value)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");
            if (String.IsNullOrWhiteSpace(value)) throw new ArgumentException("value");

            return this.Claims.Any(x => x.Type == type && x.Value == value);
        }

        public IEnumerable<string> GetClaimValues(string type)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");

            var query =
                from claim in this.Claims
                where claim.Type == type
                select claim.Value;
            return query.ToArray();
        }
        
        public string GetClaimValue(string type)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");

            var query =
                from claim in this.Claims
                where claim.Type == type
                select claim.Value;
            return query.SingleOrDefault();
        }

        public void AddClaim(string type, string value)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");
            if (String.IsNullOrWhiteSpace(value)) throw new ArgumentException("value");

            if (!this.HasClaim(type, value))
            {
                Tracing.Verbose(String.Format("[UserAccount.AddClaim] {0}, {1}, {2}, {3}", Tenant, Username, type, value));

                this.Claims.Add(
                    new UserClaim
                    {
                        Type = type,
                        Value = value
                    });
            }
        }

        public void RemoveClaim(string type)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");

            var claimsToRemove =
                from claim in this.Claims
                where claim.Type == type
                select claim;
            foreach (var claim in claimsToRemove.ToArray())
            {
                Tracing.Verbose(String.Format("[UserAccount.RemoveClaim] {0}, {1}, {2}, {3}", Tenant, Username, type, claim.Value));
                this.Claims.Remove(claim);
            }
        }

        public void RemoveClaim(string type, string value)
        {
            if (String.IsNullOrWhiteSpace(type)) throw new ArgumentException("type");
            if (String.IsNullOrWhiteSpace(value)) throw new ArgumentException("value");

            var claimsToRemove =
                from claim in this.Claims
                where claim.Type == type && claim.Value == value
                select claim;
            foreach (var claim in claimsToRemove.ToArray())
            {
                Tracing.Verbose(String.Format("[UserAccount.RemoveClaim] {0}, {1}, {2}, {3}", Tenant, Username, type, value));
                this.Claims.Remove(claim);
            }
        }

        static readonly string[] UglyBase64 = { "+", "/", "=" };
        static string StripUglyBase64(string s)
        {
            if (s == null) return s;
            foreach (var ugly in UglyBase64)
            {
                s = s.Replace(ugly, "");
            }
            return s;
        }
    }
}
