var assert = require('assert');
var rimraf = require('rimraf');
var Api = require('../src/api.js');

var directory = __dirname + '/shadow';
var api;

var test = function(cb) {
  var email = 'thaddee.tyl@example.com';
  api.login(function(err, token) {
    if (err != null) { throw err; }
    api.proveEmail({
      token: token,
      email: email,
      subject: function() { return '[example] Identity check'; },
      textMessage: function(linkToken) {
        return 'Click: https://127.0.0.1/' + linkToken;
      },
      htmlMessage: function(linkToken) {
        return 'Click: https://127.0.0.1/' + linkToken;
      },
    }, function(err, linkToken) {
      if (err != null) { throw err; }

      api.confirmEmail(linkToken, function(err, valid, session) {
        if (err != null) { throw err; }
        assert(valid, 'Email confirmation should succeed');
        assert(session.emailVerified(), 'Email should be verified');
        assert.equal(session.email, email, 'Email should be stored');

        api.authenticate(token, function(err, valid, session) {
          if (err != null) { throw err; }
          assert(valid, 'Login authentication should succeed');
          cb();
        });
      });
    });
  });
};

var setup = function(cb) {
  api = new Api({directory: directory, mailer: {block: true}}, cb);
};

// Testing has now ended. Let's clean up.
var setdown = function(cb) {
  rimraf(directory, cb);
};

var runTest = function(cb) {
  setup(function(err) {
    if (err != null) { throw err; }
    test(function(err) {
      if (err != null) { throw err; }
      setdown(function(err) {
        if (err != null) { throw err; }
        cb();
      });
    });
  });
};

module.exports = runTest;
