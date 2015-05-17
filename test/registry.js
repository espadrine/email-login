var assert = require('assert');
var TokenRegistry = require('../src/registry').TokenRegistry;
var base64url = require('../src/registry').base64url;

var test = function() {

  // Create a fake email.
  var tokenRegistry = new TokenRegistry(__dirname + '/shadow');
  var email = 'thaddee.tyl@example.com';
  tokenRegistry.login(email, function(err, loginSecret) {
    assert.ifError(err);
    var loginToken = base64url(loginSecret);

    // Send an email with
    // https://example.com/$login/?email=email&token=loginToken
    // Then they click on the link, and it gets checked:
    tokenRegistry.loginAuth(email, loginToken, function(err, authorized) {
      assert.ifError(err);
      assert.equal(authorized, true, 'Login authorization should succeed');

      tokenRegistry.reset(email, function(err, secret) {
        assert.ifError(err);
        var authToken = secret.toString('base64');
        // Redirecting to a page with a session cookie with authToken
        // Then they try to login:
        tokenRegistry.auth(email, authToken, function(err, authorized) {
          assert.ifError(err);
          assert.equal(authorized, true, 'Authorization should succeed');
        });
      });
    });
  });

};

module.exports = test;
