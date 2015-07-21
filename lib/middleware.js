var _ = require('lodash');
var bodyParser = require('body-parser');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var requestEnsure = require('req-ensure');

require('simple-errors');

module.exports = function(options) {
  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password',
    sessionTimeout: 30 * 60,
    authenticatedUrl: '/'
  });

  var ldapAuth = require('./ldap')(options.ldap);
  // var bodyParser = require('body-parser').urlencoded({extended: false});

  return function(req, res, next) {
    if (req.session)
      return next(Error.create("Session middleware has already executed"));

    req.ext.requestHandler = "ldap-auth";

    // Ensure the request has session, and json body
    ensureReqMiddleware(['session', 'cookies', 'body:urlencoded'], {
      session: {
        store: req.app.settings.sessionStore,
        cookie: {
          maxAge: options.sessionTimeout * 1000
          secure: true
        }
      }
    }, function(req, res, function() {
      var username = req.body[options.usernameProperty];
      var password = req.body[options.passwordProperty];

      if (_.isEmpty(username))
        return next(Error.http(401, "Username missing", {code: "usernameMissing"}));
      else if (_.isEmpty(password))
        return next(Error.http(401, "Password missing", {code: "passwordMissing"}));

      ldapAuth(username, password, function(err, user) {
        if (err) return next(err);

        if (!user)
          return next(Error.http(401, "Could not authenticate", {code: "invalidCredentials"}));

        req.session = user;
        // req.ext.user = user;

        if (req.cookies.returnUrl)
          res.redirect(req.cookies.returnUrl);
        else
          res.redirect(options.authenticatedUrl);
      });
    });
  };
};
