const assert = require('assert');
const rimraf = require('rimraf');
const registry = require('../src/registry');
const Registry = registry.Registry;
const base64url = registry.base64url;

const directory = __dirname + '/shadow';

describe("Registry", function() {
  let tokenRegistry;
  before("Set up the database", function(resolve) {
    tokenRegistry = new Registry(directory);
    tokenRegistry.setup(resolve);
  });

  after("Clean up the database", function(resolve) {
    rimraf(directory, resolve);
  });

  it("should perform a normal flow", function(resolve) {
    // Create a fake email.
    const email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      const token = loginSecret.toString('base64');

      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        const emailToken = emailSecret.toString('base64');

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
              let invalidToken = '';
              for (let i = 0; i < token.length; i++) {
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

  it("should remove the account", function(resolve) {
    const email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      const token = loginSecret.toString('base64');
      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        const emailToken = emailSecret.toString('base64');
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

  it("should rely on the proof lifespan", function(resolve) {
    const email = 'thaddee.tyl@example.com';
    tokenRegistry.login(function(err, loginSecret, session) {
      if (err != null) { throw err; }
      const token = loginSecret.toString('base64');
      tokenRegistry.proof(email, function(err, emailSecret, emailSession) {
        if (err != null) { throw err; }
        const emailToken = emailSecret.toString('base64');

        // Check that we go past the lifespan.
        const realCurTime = registry.currentTime;
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
});
