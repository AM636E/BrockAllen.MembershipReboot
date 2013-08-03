﻿using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;
using BrockAllen.MembershipReboot.Mvc.Areas.UserAccount.Models;

namespace BrockAllen.MembershipReboot.Mvc.Areas.UserAccount.Controllers
{
    [Authorize]
    public class ChangeUsernameController : Controller
    {
        UserAccountService userAccountService;
        AuthenticationService authSvc;

        public ChangeUsernameController(
            UserAccountService userAccountService, AuthenticationService authSvc)
        {
            this.userAccountService = userAccountService;
            this.authSvc = authSvc;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.userAccountService.TryDispose();
                this.userAccountService = null;
                this.authSvc.TryDispose();
                this.authSvc = null;
            }
            base.Dispose(disposing);
        }


        public ActionResult Index()
        {
            return View("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(ChangeUsernameInputModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    this.userAccountService.ChangeUsername(User.GetUserID(), model.NewUsername);
                    this.authSvc.SignIn(User.GetUserID());
                    return RedirectToAction("Success");
                }
                catch (ValidationException ex)
                {
                    ModelState.AddModelError("", ex.Message);
                }
            }

            return View("Index", model);
        }

        public ActionResult Success()
        {
            return View("Success", (object)User.Identity.Name);
        }
    }
}
