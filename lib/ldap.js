var ldap = require('ldapjs');
var async = require('async');
var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth:ldap');

require('simple-errors');

module.exports = function(ldapOptions) {
  // Normalize all option values as lower case strings.
  ldapOptions = _.mapValues(ldapOptions, function(optionValue) {
    if (_.isString(optionValue))
      return optionValue.toLowerCase();
    else
      return optionValue;
  });

  return function(username, password, callback) {
    var client;
    try {
      client = ldap.createClient(ldapOptions);
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

    authenticateUser(client, username, password, function(err, success) {
      if (err || success !== true) {
        client.unbind();
        return callback(err);
      }

      // The username for authenticating might be in the form DOMAIN\username.
      // But to search on samaccountname, we need just the username part.
      var backslashIndex = username.indexOf('\\');
      if (backslashIndex !== -1)
        username = username.slice(backslashIndex + 1);

      // Once the user is successully authenticated, gather up all the groups
      // they are a member of.
      getGroupsUserIsMemberOf(client, username, function(err, groups) {
        client.unbind();

        if (err)
          return callback(err);

        callback(null, {
          username: username,
          groups: groups
        });
      });
    });
  };

  function authenticateUser(client, username, password, callback) {
    debug("authenticating user %s", username);
    client.bind(username, password, function(err) {
      if (err) {
        if (err.toString().indexOf('InvalidCredentialsError') !== -1) {
          debug("invalid credentials for user %s", username);
          return callback(null, false);
        }

        return callback(err);
      }

      debug("user authenticated");
      callback(null, true);
    });
  }

  function getGroupsUserIsMemberOf(client, username, callback) {
    getUserGroups(client, username, function(err, groups) {
      if (err) return callback(err);

      var alreadyDiscoveredGroups = groups;
      var newlyDiscoveredGroups = groups;

      // Recursively discover all the effective groups a user is a member of by
      // analyzing what group each group belongs to until we've not found any
      // new groups.
      async.whilst(function() {
        return newlyDiscoveredGroups.length > 0;
      }, function(cb) {
        // Eliminate any newly discovered groups that we've already found the parents for.
        var tempGroups = [];
        async.each(newlyDiscoveredGroups, function(group, cb1) {
          getGroupGroups(client, group, function(err, groups) {
            if (err) return cb1(err);

            tempGroups = tempGroups.concat(groups);
            cb1();
          });
        }, function(err) {
          if (err) return cb(err);

          newlyDiscoveredGroups = _.difference(tempGroups, alreadyDiscoveredGroups);
          debug("found %s newly discovered groups", newlyDiscoveredGroups.length);

          if (newlyDiscoveredGroups.length > 0) {
            alreadyDiscoveredGroups = alreadyDiscoveredGroups.concat(newlyDiscoveredGroups);
          }

          cb();
        });
      }, function(err) {
        if (err) return callback(err);

        callback(null, alreadyDiscoveredGroups);
      });
    });
  }

  function getUserGroups(client, username, callback) {
    debug("get direct group membership for user %s", username);
    var opts = {
      scope: 'sub',
      filter: '(&(objectcategory=person)(objectclass=user)(samaccountname=' + username + '))'
    };

    client.search(ldapOptions.usersDN, opts, function(err, res){
      if (err) {
        return callback(err);
      }

      var groups = [];
      res.on('searchEntry', function(entry) {
        debug("got search entry");
        groups = groups.concat(extractGroupsFromEntry(entry, groups));
      });

      res.on('error', function(err) {
        callback(err);
      });

      res.on('end', function() {
        callback(null, groups);
      });
    });
  }

  function getGroupGroups(client, groupName, callback) {
    debug("get groups for group %s", groupName);
    debugger;
    var opts = {
      scope: 'sub',
      filter: '(&(objectclass=group)(cn=' + groupName + '))'
    };

    client.search(ldapOptions.groupsDN, opts, function(err, res){
      if (err) {
        return callback(err);
      }

      var groups = [];
      res.on('searchEntry', function(entry) {
        groups = groups.concat(extractGroupsFromEntry(entry));
      });

      res.on('error', function(err) {
        callback(err);
      });

      res.on('end', function() {
        callback(null, groups);
      });
    });
  }

  function extractGroupsFromEntry(entry) {
    var memberOf = entry.object.memberOf;
    if (_.isString(memberOf))
      memberOf = [memberOf];

    if (_.isArray(memberOf) === false)
      return [];

    var groups = [];
    memberOf.forEach(function(group) {
      // Value of group will look something like: CN=Group Name,OU=Groups,OU=Accounts,DC=company,DC=net
      // Make sure the group is part of the groupsDN to avoid picking up
      // things like distribution lists.
      debugger;
      if (group.toLowerCase().indexOf(ldapOptions.groupsDN) !== -1) {
        // Parse the CN of the group out of the string
        var match = group.match(/CN=([^,$]*)/i);
        if (match && match.length === 2)
          groups.push(match[1]);
      }
    });

    return groups;
  }
};
