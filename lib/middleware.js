var _ = require('lodash');
var bodyParser = require('body-parser');

require('simple-errors');

module.exports = function(options) {
  if (!options.ldap)
    throw new Error("Missing ldap object setting");

  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password',
    usernamePrefix: ''
  });

  var ldapAuth = require('./ldap')(options.ldap);

  // Ensure the username prefix is also lowercase
  options.usernamePrefix = options.usernamePrefix.toLowerCase();

  var bodyParser = require('body-parser').urlencoded({extended: false});

  return function(req, res, next) {
    bodyParser(req, res, function() {
      var username = req.body[options.usernameProperty];
      var password = req.body[options.passwordProperty];

      if (_.isEmpty(username))
        return next(Error.http(401, "Username missing", {code: "usernameMissing"}));
      else if (_.isEmpty(password))
        return next(Error.http(401, "Password missing", {code: "passwordMissing"}));

      ldapAuth(getUsernameForAuth(username), password, function(err, user) {
        if (err) return next(err);

        if (!user)
          return next(Error.http(401, "Could not authenticate", {code: "invalidCredentials"}));

        req.ext.user = user;
        next();
      });
    });
  };

  function getUsernameForAuth(username) {
    // Normalize the username to lowercase
    username = username.toLowerCase();

    // If there is a username prefix, prepend it if it isn't already present.
    // This is useful for Active Dirctory auth where the domain is part
    // of the username but you don't want users to have to type it everytime.
    var actualUsername;
    if (options.usernamePrefix) {
      if (username.slice(0, options.usernamePrefix.length) === options.usernamePrefix) {
        actualUsername = username;
        username = username.slice(options.usernamePrefix.length);
      }
      else {
        actualUsername = options.usernamePrefix + username;
      }
    }
    else
      actualUsername = username;

    return actualUsername;
  }
};
