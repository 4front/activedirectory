var assert = require('assert');
var express = require('express');
var mockery = require('mockery');
var sinon = require('sinon');
var supertest = require('supertest');
var bodyParser = require('body-parser');
var util = require('util');

describe('ldap', function() {
  var self;

  var creds = {
    username: 'test-user',
    password: 'password'
  };

  var mockLdapLogin = sinon.spy(function(username, password, callback) {
    if (username === creds.username && password === creds.password) {
      return callback(null, {
        username: creds.username
      });
    }

    callback(null);
  });

  before(function() {
    self = this;

    mockery.enable({
      warnOnUnregistered: false
    });

    mockery.registerMock('./ldap', function(ldapOptions) {
      return mockLdapLogin;
    });
  });

  after(function() {
    mockery.disable();
  });

  beforeEach(function() {
    self = this;

    mockLdapLogin.reset();
    this.server = express();

    this.server.use(function(req, res, next) {
      req.ext = {};
      next();
    });

    this.server.post('/login', require('../lib/middleware')({}));

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
  });

  it('logs user in successfully', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: creds.password})
      .expect(200)
      .expect(function(res) {
        assert.ok(mockLdapLogin.calledWith(creds.username, creds.password));

        assert.deepEqual(res.body.user, {
          username: creds.username
        });
      })
      .end(done);
  });

  it('returns 401 error for incorrect password', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: 'wrong_password'})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'invalidCredentials');
      })
      .end(done);
  });

  it('returns 401 error for missing username', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({password: creds.password})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'usernameMissing');
      })
      .end(done);
  });

  it('returns 401 error for missing password', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username})
      .expect(401)
      .expect(function(res) {
        assert.equal(res.body.code, 'passwordMissing');
      })
      .end(done);
  });
});
