var assert = require('assert');
var mockery = require('mockery');
var sinon = require('sinon');
var util = require('util');
var _ = require('lodash');
var debug = require('debug')('4front:ldap-auth:test');
var EventEmitter = require('events').EventEmitter;

require('dash-assert');

var ldapOptions = {
  url: 'ldap://test.net',
  baseDN: 'DC=company,DC=net',
  usersDN: 'OU=Users,OU=Accounts,DC=company,DC=net',
  groupsDN: 'OU=Users,OU=Accounts,DC=company,DC=net',
  usernamePrefix: 'domain\\'
};

var userCreds = {
  username: 'test-user',
  password: 'password'
};

var ldapSearchResponses = {
  '(&(objectcategory=person)(objectclass=user)(samaccountname=test-user))': [{
    object: {
      memberOf: [
        'CN=group1,' + ldapOptions.groupsDN,
        'CN=group2,' + ldapOptions.groupsDN,
        'CN=group3,' + ldapOptions.groupsDN
      ]
    }
  }],
  '(&(objectclass=group)(cn=group1))': [{
    object: {
      memberOf: [
        'CN=group11,' + ldapOptions.groupsDN,
        'CN=group12,' + ldapOptions.groupsDN
      ]
    }
  }],
  '(&(objectclass=group)(cn=group2))': [{
    object: {
      memberOf: [
        'CN=group21,' + ldapOptions.groupsDN,
        'CN=group22,' + ldapOptions.groupsDN
      ]
    }
  }],
  '(&(objectclass=group)(cn=group11))': [{
    object: {
      memberOf: [
        'CN=group111,' + ldapOptions.groupsDN
      ]
    }
  }],
  '(&(objectclass=group)(cn=group21))': [{
    object: {
      memberOf: [
        'CN=group211,' + ldapOptions.groupsDN
      ]
    }
  }],
  '(&(objectclass=group)(cn=group111))': [{
    object: {
      memberOf: [
        'CN=group1111,' + ldapOptions.groupsDN
      ]
    }
  }]
};

describe('ldap', function() {
  var self;

  var ldapMock = {};

  before(function() {
    mockery.enable({
      warnOnUnregistered: false
    });

    mockery.registerMock('ldapjs', ldapMock);
  });

  after(function() {
    mockery.disable();
  });

  beforeEach(function() {
    self = this;
    this.mockClient = new MockLdapClient();

    ldapMock.createClient = sinon.spy(function(opts) {
      return self.mockClient;
    });

    this.ldap = require('../lib/ldap')(ldapOptions);
  });

  it('fails with invalid credentials', function(done) {
    this.ldap(ldapOptions.usernamePrefix + userCreds.username, "wrong_password", function(err, user) {
      if (err) return done(err);

      assert.isUndefined(user);
      done();
    });
  });

  it('logs user in with usernamePrefix specified', function(done) {
    this.ldap(ldapOptions.usernamePrefix + userCreds.username, userCreds.password, function(err, user) {
      if (err) return done(err);

      assert.isTrue(self.mockClient.bind.calledWith(
        ldapOptions.usernamePrefix + userCreds.username, userCreds.password));

      done();
    });
  });

  it('logs user in and gets groups', function(done) {
    this.ldap(userCreds.username, userCreds.password, function(err, user) {
      if (err) return done(err);

      assert.ok(user);
      assert.isTrue(self.mockClient.bind.called);
      assert.isTrue(self.mockClient.bind.calledWith(
        ldapOptions.usernamePrefix + userCreds.username, userCreds.password));

      assert.equal(userCreds.username, userCreds.username);
      assert.noDifferences(user.groups, ['group1', 'group2', 'group3', 'group11', 'group12',
        'group21', 'group22', 'group111', 'group211', 'group1111']);
      done();
    });
  });
});

var MockLdapClient = function() {};
util.inherits(MockLdapClient, EventEmitter);

MockLdapClient.prototype.bind = sinon.spy(function(username, password, callback) {
  console.log("mock bind");
  if (username === ldapOptions.usernamePrefix + userCreds.username && password === userCreds.password)
    callback();
  else
    callback(new Error("InvalidCredentialsError"));
});

MockLdapClient.prototype.search = sinon.spy(function(dn, opts, callback) {
  var searchEntries = ldapSearchResponses[opts.filter] || [];
  var res = new MockLdapResponse();

  setTimeout(function() {
    searchEntries.forEach(function(entry) {
      res.emit('searchEntry', entry);
    });

    res.emit('end');
  }, 20);

  callback(null, res);
});

MockLdapClient.prototype.unbind = sinon.spy(function() {});

var MockLdapResponse = function(){};
util.inherits(MockLdapResponse, EventEmitter);
