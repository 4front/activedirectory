var assert = require('assert');
var express = require('express');
var mockery = require('mockery');
var sinon = require('sinon');
var supertest = require('supertest');
var bodyParser = require('body-parser');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

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

    this.username = 'test-user';
    this.password = 'password';


    this.server = express();

    this.server.use(function(req, res, next) {
      req.ext = {};
      next();
    });

    this.server.post('/login', require('..')({
      ldap: {
        url: 'ldap://test.net',
        baseDN: 'CN=users.DC=test.DC=net'
      }
    }));

    this.server.use(function(req, res, next) {
      res.json(req.ext);
    });

    this.server.use(function(err, req, res, next) {
      if (!err.status)
        err.status = 500;

      res.statusCode = err.status;
      if (err.status < 500)
        res.json(err);
      else {
        console.error(err);
        res.json({});
      }
    });

    this.mockClient = new MockLdapClient(this.username, this.password);

    ldapMock.createClient = sinon.spy(function(opts) {
      return self.mockClient;
    });
  });


  it('logs user in successfully', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: this.username, password: this.password})
      .expect(200)
      .expect(function(res) {
        assert.ok(self.mockClient.bind.calledWith(self.username, self.password));
        assert.ok(self.mockClient.unbind.called);

        assert.deepEqual(res.body.user, {
          userId: self.username,
          username: self.username
        });
      })
      .end(done);
  });

  it('returns 401 error for incorrect password', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: this.username, password: 'wrong_password'})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'invalidCredentials');
      })
      .end(done);
  });

  it('returns 401 error for missing username', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({password: this.password})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'usernameMissing');
      })
      .end(done);
  });

  it('returns 401 error for missing password', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: this.username})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'passwordMissing');
      })
      .end(done);
  });
});

var MockLdapClient = function(username, password) {
  this.username = username;
  this.password = password;
};
util.inherits(MockLdapClient, EventEmitter);

MockLdapClient.prototype.bind = sinon.spy(function(username, password, callback) {
  if (username === this.username && password === this.password)
    callback(null);
  else
    callback(new Error("InvalidCredentialsError"));
});

MockLdapClient.prototype.unbind = sinon.spy(function() {});
