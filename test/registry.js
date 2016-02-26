var assert = require('assert');
var rimraf = require('rimraf');
if (this.Promise === undefined) {
  this.Promise = require('promise');
  require('promise/lib/rejection-tracking').enable();
}
var registry = require('../src/registry');
var Registry = registry.Registry;
var base64url = registry.base64url;

var directory = __dirname + '/shadow';
var tokenRegistry;

var normalFlowTest = function() {
  return new Promise(function(resolve) {
    // Create a fake email.
    var email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      var token = loginSecret.toString('base64');

      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        var emailToken = emailSecret.toString('base64');

        // Send an email with something like
        // https://example.com/login/?id=id&token=emailToken
        // Then they click on the link, and it gets checked:
        tokenRegistry.auth(emailSession.id, emailToken,
        function(err, valid) {
          if (err != null) { throw err; }
          assert(valid, 'Email confirmation should succeed');

          tokenRegistry.confirmEmailProved(session.id, email, function(err, session) {
            if (err != null) { throw err; }
            assert(session.emailVerified(), 'Email should be verified');
            assert.equal(session.email, email, 'Email should be stored');

            // Redirecting to a page with a token cookie.
            // Then they try to login:
            tokenRegistry.auth(session.id, token, function(err, valid, session) {
              if (err != null) { throw err; }
              assert(valid, 'Authentication should succeed');
              assert(session.lastAuth > 0, 'Last authentication date was registered');

              // Check that we cannot authorize an invalid token.
              var invalidToken = '';
              for (var i = 0; i < token.length; i++) {
                invalidToken += '0';
              }
              tokenRegistry.auth(session.id, invalidToken, function(err, valid) {
                if (err != null) { throw err; }
                assert.equal(valid, false, 'Authentication should fail');

                // Testing a logout.
                tokenRegistry.logout(session.id, function(err) {
                  if (err != null) { throw err; }
                  tokenRegistry.load(session.id, function(err) {
                    assert(err != null, 'Logout should delete the session');
                    resolve();
                  });
                });
              });
            });
          });
        });
      });
    });
  });
};

var rmAccountTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      var token = loginSecret.toString('base64');
      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        var emailToken = emailSecret.toString('base64');
        tokenRegistry.auth(emailSession.id, emailToken, function(err, valid) {
          if (err != null) { throw err; }

          tokenRegistry.rmAccount(email, function(err) {
            if (err != null) { throw err; }
            tokenRegistry.loadAccount(email, function(err) {
              assert(err != null, 'rmAccount should delete the account');
              resolve();
            });
          });
        });
      });
    });
  });
};

var proofLifespanTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      var token = loginSecret.toString('base64');
      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        var emailToken = emailSecret.toString('base64');

        // Check that we go past the lifespan.
        var realCurTime = registry.currentTime;
        registry.changeCurrentTime(function() {
          return realCurTime() + registry.PROOF_LIFESPAN + 1;
        });
        tokenRegistry.auth(emailSession.id, emailToken, function(err, valid) {
          if (err != null) { throw err; }
          registry.changeCurrentTime(realCurTime);
          assert(!valid, 'Confirming after the proof lifespan should fail');
          resolve();
        });
      });
    });
  });
};

var test = function() {
  return normalFlowTest()
    .then(rmAccountTest)
    .then(proofLifespanTest);
};


var setup = function() {
  return new Promise(function(resolve, reject) {
    tokenRegistry = new Registry(directory);
    tokenRegistry.setup(function(err) {
      if (err != null) { reject(err); }
      else { resolve(); }
    });
  });
};

// Testing has now ended. Let's clean up.
var setdown = function() {
  return new Promise(function(resolve, reject) {
    rimraf(directory, function(err) {
      if (err != null) { reject(err); }
      else { resolve(); }
    });
  });
};

var runTest = function(cb) {
  setup()
  .then(test)
  .then(setdown)
  .then(cb)
  .catch(function(err) { throw err; });
};

module.exports = runTest;
