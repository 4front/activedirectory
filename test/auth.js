var assert = require('assert');
var express = require('express');
var mockery = require('mockery');
var sinon = require('sinon');
var supertest = require('supertest');
var bodyParser = require('body-parser');
var ActiveDirectory = require('activedirectory');

describe('ActiveDirectory', function() {
  var self;

  var ActiveDirectoryMock = function(){};

  before(function() {
    mockery.enable({
      warnOnUnregistered: false
    });

    mockery.registerMock('activedirectory', ActiveDirectoryMock);
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
      ldapUrl: 'ldap://test.net',
      ldapBaseDN: 'CN=users.DC=test.DC=net'
    }));

    this.server.use(function(req, res, next) {
      res.json(req.ext);
    });

    this.authenticate = sinon.spy(function(username, password, callback) {
      if (username === self.username && password === self.password)
        callback();
      else {
        callback(new Error("InvalidCredentials"));
      }
    });

    ActiveDirectoryMock.prototype.authenticate = this.authenticate;
  });

  it('logs user in successfully', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: this.username, password: this.password})
      .expect(200)
      .expect(function(res) {
        assert.ok(self.authenticate.calledWith(self.username, self.password));

        assert.deepEqual(res.body.user, {
          userId: self.username,
          username: self.username
        });
      })
      .end(done);
  });
});
