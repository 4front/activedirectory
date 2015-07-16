var _ = require('lodash');
var bodyParser = require('body-parser');

require('simple-errors');

module.exports = function(options) {
  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password'
  });

  var ldapAuth = require('./ldap')(options.ldap);
  var bodyParser = require('body-parser').urlencoded({extended: false});

  return function(req, res, next) {
    bodyParser(req, res, function() {
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

        req.ext.user = user;
        next();
      });
    });
  };
};
