var _ = require('lodash');
var ActiveDirectory = require('activedirectory');
var debug = require('debug');

require('simple-errors');

module.exports = function(options) {
  if (!options.ldapBaseDN)
    throw new Error("Missing ldapBaseDN setting");

  if (!options.ldapUrl)
    throw new Error("Missing ldapBaseDN setting");

  var ad = new ActiveDirectory({
    url: options.ldapUrl,
    baseDN: options.ldapBaseDN
  });

  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password'
  });

  var bodyParser = require('body-parser').urlencoded({extended: false});

  return function(req, res, next) {
    bodyParser(req, res, function() {
      var username = req.body[options.usernameProperty];
      var password = req.body[options.passwordProperty];

      if (_.isEmpty(username))
        return next(Error.http(401, "Username missing", {code: "usernameMissing"}));
      else if (_.isEmpty(password))
        return next(Error.http(401, "Password missing", {code: "passwordMissing"}));

      ad.authenticate(username, password, function(err, authenticated) {
        if (err) {
          if (/InvalidCredentialsError/.test(err.toString()))
            return next(Error.http(401, "Invalid credentials", {code: "invalidCredentials"}));
          else
            return next(err);
        }

        debug("user %s authenticated", username);
        req.ext.user = {
          userId: username,
          username: username
        };

        next();
      });
    });
  };
};
