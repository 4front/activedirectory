var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth');

require('simple-errors');

module.exports = function(options) {
  if (!options.ldap)
    throw new Error("Missing ldap object setting");

  // The main export is the middleware function so it can be declared in package.json router.
  var exports = require('./lib/middleware')(options);

  // Expose the authenticate function so it can be invoked in non-middleware scenarios.
  exports.authenticate = require('./lib/ldap')(options.ldap);

  // Translate the username to the unique userId. In the case of LDAP just assume that the
  // userId and the username are the same.
  exports.getUserId = function(username, callback) {
    callback(null, username);
  };

  exports.providerName = 'ldap';

  return exports;
};
