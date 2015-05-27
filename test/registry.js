var assert = require('assert');
var rimraf = require('rimraf');
var Registry = require('../src/registry').Registry;
var base64url = require('../src/registry').base64url;

var directory = __dirname + '/shadow';
var tokenRegistry;

var test = function(cb) {

  // Create a fake email.
  var email = 'thaddee.tyl@example.com';
  tokenRegistry.login(email, function(err, loginSecret) {
    if (err != null) { throw err; }
    var loginToken = base64url(loginSecret);

    // Send an email with
    // https://example.com/$login/?email=email&token=loginToken
    // Then they click on the link, and it gets checked:
    tokenRegistry.confirm(email, loginToken, function(err, authorized) {
      if (err != null) { throw err; }
      assert.equal(authorized, true, 'Login authorization should succeed');

      tokenRegistry.reset(email, function(err, secret) {
        if (err != null) { throw err; }
        var authToken = secret.toString('base64');

        // Redirecting to a page with a session cookie with authToken
        // Then they try to login:
        tokenRegistry.auth(email, authToken, function(err, authorized) {
          if (err != null) { throw err; }
          assert.equal(authorized, true, 'Authorization should succeed');

          // Check that we cannot authorize an invalid token.
          var invalidToken = '';
          for (var i = 0; i < authToken.length; i++) {
            invalidToken += '0';
          }
          tokenRegistry.auth(email, invalidToken, function(err, authorized) {
            if (err != null) { throw err; }
            assert.equal(authorized, false, 'Authorization should fail');
            cb();
          });
        });
      });
    });
  });

};

var setup = function(cb) {
  tokenRegistry = new Registry(directory);
  tokenRegistry.mkdir(cb);
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
