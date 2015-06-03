var assert = require('assert');
var activeDirectory = require('..');

describe('ActiveDirectory', function() {
  it('logs user in', function(done) {
    var ad = activeDirectory({
      ldapUrl: 'ldap://LDAP0319.nordstrom.net',
      ldapBaseDN: 'CN=users,DC=nordstrom,DC=net'
    });

    ad.authenticate(username, password, function(err, user) {
      if (err)
        return done(err);

      console.log("user %o authenticated!", user);
      done();
    });
  });
});
