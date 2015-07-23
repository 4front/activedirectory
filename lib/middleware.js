var _ = require('lodash');
var bodyParser = require('body-parser');

require('simple-errors');

module.exports = function(options) {
  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password'
  });

  return function(req, res, next) {
    if (!req.session)
      return next(Error.http(501, "The ldap-auth middleware requires the session plugin to be declared earlier in the array."));

    var ldapAuth = require('./ldap')(_.merge({}, req.app.settings.ldap, options));

    bodyParser.urlencoded({extended: false})(req, res, function() {
      var username = req.body[options.usernameProperty];
      var password = req.body[options.passwordProperty];

      if (_.isEmpty(username))
        return next(Error.http(401, "Username missing", {code: "usernameMissing"}));
      else if (_.isEmpty(password))
        return next(Error.http(401, "Password missing", {code: "passwordMissing"}));

      ldapAuth(username, password, function(err, user) {
        if (err) return next(err);

        if (!user) {
          if (options.failureUrl)
            return res.redirect(options.failureUrl);
          else
            return next(Error.http(401, "Could not authenticate", {code: "invalidCredentials"}));
        }

        // Set the user in session state
        req.session.user = user;

        if (options.successUrl) {
          // If there is a returnUrl in the cookie, redirect there.
          if (req.cookies.returnUrl)
            res.redirect(req.cookies.returnUrl);
          else
            res.redirect(options.successUrl);
        }
        else {
          res.json({
            user: user
          });
        }
      });
    });
  };
};
