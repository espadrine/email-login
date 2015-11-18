var assert = require('assert');
var rimraf = require('rimraf');
var Promise = require('promise');
var Api = require('../src/api.js');

var directory = __dirname + '/shadow';
var api;

var normalFlowTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    api.login(function(err, token) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
        htmlMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
      }, function(err, emailToken) {
        if (err != null) { throw err; }

        api.confirmEmail(token, emailToken, function(err, token, session) {
          if (err != null) { throw err; }
          assert(!!token, 'Email confirmation should succeed');
          assert(session.emailVerified(), 'Email should be verified');
          assert.equal(session.email, email, 'Email should be stored');

          api.authenticate(token, function(err, valid, session) {
            if (err != null) { throw err; }
            assert(valid, 'Login authentication should succeed');

            api.logout(token, function(err) {
              if (err != null) { throw err; }
              api.authenticate(token, function(err, valid, session) {
                assert(!valid, 'Logout should delete the session');
                resolve();
              });
            });
          });
        });
      });
    });
  });
};

var wrongConfirmationTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    api.login(function(err, token, session) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
        htmlMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
      }, function(err, emailToken) {
        if (err != null) { throw err; }

        // Check that we cannot authorize an invalid token.
        var secret = '';
        for (var i = 0; i < 32; i++) {
          secret += '0';
        }
        emailToken = Api.encodeToken(session.id, secret);

        api.confirmEmail(token, emailToken,
        function(err, newToken, newSession) {
          if (err != null) { throw err; }
          assert(!newToken,
            'Email confirmation should fail from wrong token');
          resolve();
        });
      });
    });
  });
};

var unknownDeviceConfirmationTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    api.login(function(err, token, session) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
        htmlMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
      }, function(err, emailToken) {
        if (err != null) { throw err; }

        api.confirmEmail(undefined, emailToken,
        function(err, newToken, newSession, session) {
          if (err != null) { throw err; }
          assert(!!newToken,
            'Email confirmation should succeed from unknown device');
          assert.notEqual(token, newToken,
            'Email confirmation give distinct token to unknown device');
          assert(session.emailVerified(),
            'Email should be verified for known device');
          assert.equal(session.email, email,
            'Email should be stored for known device');
          assert(newSession.emailVerified(),
            'Email should be verified for unknown device');
          assert.equal(newSession.email, email,
            'Email should be stored for unknown device');
          resolve();
        });
      });
    });
  });
};

var wrongDeviceConfirmationTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    api.login(function(err, token, session) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
        htmlMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
      }, function(err, emailToken) {
        if (err != null) { throw err; }

        // New device, used for confirmation.
        api.login(function(err, otherToken, newSession) {
          if (err != null) { throw err; }

          api.confirmEmail(otherToken, emailToken,
          function(err, newToken, newSession) {
            if (err != null) { throw err; }
            api.session(session.id, function(err, session) {
              if (err != null) { throw err; }
              assert(!!newToken,
                'Email confirmation should succeed from wrong device');
              assert.notEqual(token, newToken,
                'Email confirmation give distinct token to wrong device');
              assert(session.emailVerified(),
                'Email should be verified for right device');
              assert.equal(session.email, email,
                'Email should be stored for right device');
              assert(newSession.emailVerified(),
                'Email should be verified for wrong device');
              assert.equal(newSession.email, email,
                'Email should be stored for wrong device');
              resolve();
            });
          });
        });
      });
    });
  });
};

var deleteSessionTest = function() {
  return new Promise(function(resolve) {
    api.login(function(err, token, session) {
      if (err != null) { throw err; }
      // Check that we can remove the account.
      api.deleteSession(session.id, function(err) {
        if (err != null) { throw err; }
        api.authenticate(token, function(err, valid, session) {
          assert(!valid, 'deleteSession should delete the session');
          resolve();
        });
      });
    });
  });
};

var deleteAccountTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    api.login(function(err, token, session) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
        htmlMessage: function(emailToken) {
          return 'Click: https://127.0.0.1/' + emailToken;
        },
      }, function(err, emailToken) {
        if (err != null) { throw err; }
        api.confirmEmail(token, emailToken,
        function(err, newToken, newSession) {
          if (err != null) { throw err; }

          // Check that we can remove the account.
          api.deleteAccount(email, function(err) {
            if (err != null) { throw err; }
            api.authenticate(token, function(err, valid, session) {
              assert(!valid, 'deleteAccount should delete the account');
              resolve();
            });
          });
        });
      });
    });
  });
};

var accountTest = function() {
  return new Promise(function(resolve) {
    var email = 'thaddee.tyl@example.com';
    var emailMessageHandler = function(emailToken) {
      return 'Click: https://127.0.0.1/' + emailToken;
    };
    api.login(function(err, token1, session1) {
      if (err != null) { throw err; }
      api.proveEmail({
        token: token1,
        email: email,
        subject: function() { return '[example] Identity check'; },
        textMessage: emailMessageHandler,
        htmlMessage: emailMessageHandler,
      }, function(err, emailToken1) {
        if (err != null) { throw err; }
        api.confirmEmail(token1, emailToken1,
        function(err, newToken, newSession) {
          if (err != null) { throw err; }
          api.login(function(err, token2, session2) {
            if (err != null) { throw err; }
            api.proveEmail({
              token: token2,
              email: email,
              subject: function() { return '[example] Identity check'; },
              textMessage: emailMessageHandler,
              htmlMessage: emailMessageHandler,
            }, function(err, emailToken2) {
              if (err != null) { throw err; }
              api.confirmEmail(token2, emailToken2,
              function(err, newToken, newSession) {
                if (err != null) { throw err; }

                // Check that we can access the account.
                api.account(email, function(err, account) {
                  if (err != null) { throw err; }
                  assert.equal(account.email, email,
                    'The account\'s email is correct');
                  assert.equal(account.sessions.length, 2,
                    'The account has 2 sessions');
                  assert.equal(account.sessions[0].id, session1.id,
                    'The first account has the correct session');
                  assert.equal(account.sessions[1].id, session2.id,
                    'The second account has the correct session');
                  resolve();
                });
              });
            });
          });
        });
      });
    });
  });
};

var test = function(cb) {
  normalFlowTest()
    .then(wrongConfirmationTest)
    .then(wrongDeviceConfirmationTest)
    .then(unknownDeviceConfirmationTest)
    .then(deleteSessionTest)
    .then(deleteAccountTest)
    .then(accountTest)
    .then(cb)
    .catch(function(err) { throw err; });
};

var setup = function(cb) {
  api = new Api({db: directory, mailer: {block: true}}, cb);
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
