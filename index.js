var ActiveDirectory = require('activedirectory');
var debug = require('debug');

module.exports = function(settings) {
  if (!settings.ldapBaseDN)
    throw new Error("Missing ldapBaseDN setting");

  if (!settings.ldapUrl)
    throw new Error("Missing ldapBaseDN setting");

  var ad = new ActiveDirectory({
    url: settings.ldapUrl,
    baseDN: settings.ldapBaseDN
  });

  return {
    name: 'Active Directory',
    authenticate: function(username, password, callback) {
      debug("authenticate user");

      ad.authenticate(username, password, function(err, authenticated) {
        if (err)
          return callback(err);

        debug("user %s authenticated", username);
        callback(null, {username: username});

        // "cn=readonly,cn=users,dc=myorg,dc=com"
        //TODO: Would be cool to lookup the user details to
        // get a nicer display name. For now just returning the
        // username itself.
        // http://stackoverflow.com/questions/17795007/node-js-ldap-auth-user
        // ad.findUser("", function(err, user) {
        //   if (err) return callback(err);
        //
        //   debugger;
        //   console.log("user %o", user);
        //
        //   // Lookup the user to get their display name?
        //   callback(null, {username: username});
        // });
      });
    }
  };
};
