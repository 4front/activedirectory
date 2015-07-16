var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth');

require('simple-errors');

module.exports = function(options) {
  // The main export is the middleware function so it can be declared in package.json router.
  var exports = require('./lib/middleware')(options);

  // Expose the authenticate function so it can be invoked in non-middleware scenarios.
  exports.authenticate = require('./lib/ldap')(options);

  // Translate the username to the unique userId. In the case of LDAP just assume that the
  // userId and the username are the same.
  exports.getUserId = function(username, callback) {
    callback(null, username);
  };

  exports.providerName = 'ldap';

  return exports;
};
