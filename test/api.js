var assert = require('assert');
var rimraf = require('rimraf');
var Api = require('../src/api.js');

var directory = __dirname + '/shadow';
var api;

var test = function(cb) {
  api.login({
    email: 'thaddee.tyl@example.com',
    subject: function() { return '[example] Identity check'; },
    textMessage: function(linkToken) { return 'Click: https://127.0.0.1/' + linkToken; },
    htmlMessage: function(linkToken) { return 'Click: https://127.0.0.1/' + linkToken; },
  }, function(err, linkToken) {
    if (err != null) { throw err; }

    api.confirm(linkToken, function(err, cookieToken) {
      if (err != null) { throw err; }
      assert.notEqual(cookieToken, undefined, 'Login confirmation should succeed');

      api.authenticate(cookieToken, function(err, email) {
        if (err != null) { throw err; }
        assert.notEqual(email, undefined, 'Login authentication should succeed');
        cb();
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
