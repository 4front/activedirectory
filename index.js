var _ = require('lodash');
var debug = require('debug');
var ldap = require('ldapjs');

require('simple-errors');

module.exports = function(options) {
  if (!options.ldap)
    throw new Error("Missing ldap object setting");

  _.defaults(options, {
    usernameProperty: 'username',
    passwordProperty: 'password',
    usernamePrefix: null
  });

  var bodyParser = require('body-parser').urlencoded({extended: false});

  var middleware = function(req, res, next) {
    bodyParser(req, res, function() {
      var username = req.body[options.usernameProperty];
      var password = req.body[options.passwordProperty];

      if (_.isEmpty(username))
        return next(Error.http(401, "Username missing", {code: "usernameMissing"}));
      else if (_.isEmpty(password))
        return next(Error.http(401, "Password missing", {code: "passwordMissing"}));

      // If there is a username prefix, prepend it if it isn't already present.
      // This is useful for Active Dirctory auth where the domain is part
      // of the username but you don't want users to have to type it everytime.
      if (options.usernamePrefix && username.slice(0, usernamePrefix.length) !== options.usernamePrefix)
        username = options.usernamePrefix + username;

      authenticate(username, password, function(err, success) {
        if (err) return next(err);

        if (success !== true)
          return next(Error.http(401, "Could not authenticate", {code: "invalidCredentials"}));

        req.ext.user = {
          userId: username,
          username: username
        };

        next();
      });
    });
  };

  function authenticate(username, password, callback) {
    var client;
    try {
      client = ldap.createClient(options.ldap);
    }
    catch (err) {
      return callback(Error.create("Could not create LDAP client", {}, err));
    }

    client.on('error', function(err) {
      // Ignore ECONNRESET errors
      if ((err || {}).errno !== 'ECONNRESET') {
        return callback(err);
      }
    });

    client.bind(username, password, function(err, result) {
      client.unbind();

      if (err) {
        if (err.toString().indexOf('InvalidCredentialsError') !== -1)
          return callback(null, false);

        return callback(err);
      }

      callback(null, true);
    });
  }

  // Expose the authenticate function so it can be invoked in non-middleware scenarios.
  middleware.authenticate = authenticate;

  return middleware;
};
