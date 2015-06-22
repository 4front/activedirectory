var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth');
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

      authenticate(username, password, function(err, user) {
        if (err) return next(err);

        if (!user)
          return next(Error.http(401, "Could not authenticate", {code: "invalidCredentials"}));

        req.ext.user = user;

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

    debug("authenticating user %s", username);
    client.bind(actualUsername, password, function(err, result) {
      client.unbind();

      if (err) {
        if (err.toString().indexOf('InvalidCredentialsError') !== -1) {
          debug("invalid credentials for user %s", username);
          return callback(null, null);
        }

        return callback(err);
      }

      // TODO: If there are additional details on the result (like email address),
      // then append them to the user object.
      var user = {
        userId: username,
        username: username
      };

      callback(null, user);
    });
  }

  // Expose the authenticate function so it can be invoked in non-middleware scenarios.
  middleware.authenticate = authenticate;

  return middleware;
};
