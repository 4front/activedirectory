var assert = require('assert');
var express = require('express');
var mockery = require('mockery');
var sinon = require('sinon');
var supertest = require('supertest');
var bodyParser = require('body-parser');
var util = require('util');

describe('ldap', function() {
  var self, middlewareOptions, sessionMiddleware;

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

    // Just for testing purposes obviously.
    this.server.settings.crypto = {
      encrypt: function(value) {
        return new Buffer(value).toString('base64');
      },
      decrypt: function(value) {
        return new Buffer(value, 'base64').toString('utf8');
      }
    };

    sessionMiddleware = require('express-session')({
      resave: false,
      secret: 'abc',
      saveUninitialized: true
    });

    this.server.use(require('cookie-parser')());
    this.server.use(function(req, res,  next) {
      if (sessionMiddleware)
        sessionMiddleware(req, res, next);
      else
        next();
    });

    this.server.use(function(req, res, next) {
      req.ext = {};
      next();
    });

    middlewareOptions = {};
    this.server.post('/login', function(req, res, next) {
      require('../lib/middleware')(middlewareOptions)(req, res, next);
    });

    this.server.use(function(req, res, next) {
      res.json(req.ext);
    });

    this.server.use(function(err, req, res, next) {
      if (!err.status)
        err.status = 500;

      res.statusCode = err.status;
      if (err.status !== 500)
        res.json(err);
      else {
        console.error(err);
        res.json({});
      }
    });
  });

  it('should redirect after successful authentication', function(done) {
    middlewareOptions.successUrl = "/";

    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: creds.password})
      .expect(302)
      .expect('Location', middlewareOptions.successUrl)
      .expect(function(res) {
        assert.ok(mockLdapLogin.calledWith(creds.username, creds.password));
      })
      .end(done);
  });

  it('should redirect to returnUrl from cookie', function(done) {
    middlewareOptions.successUrl = "/";
    var returnUrl = "/protected-page";

    supertest(this.server).post('/login')
      .set('Cookie', "returnUrl=" + encodeURIComponent(returnUrl))
      .type('form')
      .send({username: creds.username, password: creds.password})
      .expect(302)
      .expect('Location', returnUrl)
      .end(done);
  });

  it('should return user if no redirectUrl', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: creds.password})
      .expect(200)
      .expect(function(res) {
        assert.isMatch(res.body.user, {
          username: creds.username
        });
      })
      .end(done);
  });

  it('should redirect to failureUrl for incorrect password', function(done) {
    middlewareOptions.failureUrl = "/failed";

    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: 'wrong_password'})
      .expect(302)
      .expect('Location', middlewareOptions.failureUrl)
      .end(done);
  });

  it('should return 401 for incorrect password with no failureUrl', function(done) {
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

  it('should return error if no session state', function(done) {
    sessionMiddleware = null;

    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username})
      .expect(501)
      .end(done);
  });

  it('should add basicAuthToken to user if specified', function(done) {
    supertest(this.server).post('/login')
      .type('form')
      .send({username: creds.username, password: creds.password})
      .expect(200)
      .expect(function(res) {
        assert.isObject(res.body.user.basicAuthToken);

        var basicAuthToken = "Basic " + new Buffer(creds.username + ":" + creds.password).toString('base64');

        assert.deepEqual(res.body.user.basicAuthToken.__encrypted,
          self.server.settings.crypto.encrypt(basicAuthToken));
      })
      .end(done);
  });
});
