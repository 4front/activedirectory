var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth:middleware');
var bodyParser = require('body-parser');

require('simple-errors');

module.exports = function(options) {
  options = _.defaults({}, options, {
    usernameProperty: 'username',
    passwordProperty: 'password',
    saveBasicAuthToken: false
  });

  return function(req, res, next) {
    if (!req.session)
      return next(Error.http(501, "The ldap-auth middleware requires the session plugin to be declared earlier in the array."));

    // Merge together the options with the parent app ldap settings. This way
    // individual virtual apps can provide their own LDAP settings, but by
    // default the same settings used by 4front itself are used which should
    // be the most common scenario.
    var ldapSettings = _.merge({}, options, req.app.settings.ldap);
    var ldapAuth = require('./ldap')(ldapSettings);

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

        // Save the basicAuthToken on the user object for subsequent authorization
        // with APIs via the express-request-proxy that accept basic auth.
        var basicAuthToken = "Basic " + new Buffer(username + ":" + password).toString("base64");

        // Store the basicAuthToken as an encrypted object
        user.basicAuthToken = {
          '__encrypted': req.app.settings.crypto.encrypt(basicAuthToken)
        };

        // Set the user in session state
        debug("setting user in session");
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
