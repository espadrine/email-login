const assert = require('assert');
const rimraf = require('rimraf');
const Api = require('../src/api.js');
const Session = require('../src/session.js');

const directory = __dirname + '/shadow';

describe("Api", function() {
  let api;
  before("set up the database", function(resolve) {
    api = new Api({
      db: directory,
      mailer: {block: true},
      emailRateLimit: false
    }, resolve);
  });

  after("clean up the database", function(resolve) {
    rimraf(directory, resolve);
  });

  it("should perform a normal flow", function(resolve) {
    const email = 'thaddee.tyl@example.com';
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

  it("should refuse a wrong confirmation", function(resolve) {
    const email = 'thaddee.tyl@example.com';
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
        let secret = '';
        for (let i = 0; i < 16; i++) {
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

  it("should use a new session when confirming from an unknown device", function(resolve) {
    const email = 'thaddee.tyl@example.com';
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

  it("should refuse an incorrect confirmation from a wrong device", function(resolve) {
    const email = 'thaddee.tyl@example.com';
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
              assert(!session.emailVerified(),
                'Email should not be verified for right device');
              assert.equal(session.email, email,
                'Email claim should be stored for right device');
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

  it("should delete a session", function(resolve) {
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

  it("should delete an account", function(resolve) {
    const email = 'thaddee.tyl@example.com';
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

  it("should fetch account information", function(resolve) {
    const email = 'thaddee.tyl@example.com';
    const emailMessageHandler = function(emailToken) {
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
                api.setAccountData(email, {name: 'Camille'}, function(err) {
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
                    assert.equal(account.data.name, 'Camille',
                      'The account has kept its custom data');
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

  it("should read email domains", function(resolve) {
    assert.equal(api.emailDomain('a'), undefined);
    assert.equal(api.emailDomain('@a'), undefined);
    assert.equal(api.emailDomain('a@'), undefined);
    assert.equal(api.emailDomain('a@a'), '@a');
    assert.equal(api.emailDomain('@a@a'), '@a');
    assert.equal(api.emailDomain('a@a@a'), '@a');
    resolve();
  });

  it("should delay emails", function(resolve) {
    // Store the real current time.
    const currentTime = Session.currentTime;
    let time = 222;
    Session.changeCurrentTime(function() { return time; });

    const nextProofRequest = Object.create(null);
    const email = 'a@a';
    // First try: no requests are listed, there is no delay.
    assert.equal(api.emailDelay(email, nextProofRequest), 0);
    // Now, there is a request listed.
    assert.equal(nextProofRequest[email], 222);
    time++;  // A millisecond later.
    // Second try: there is a request; we must delay.
    // As guaranteed, there is 1s between the previous proof request and this.
    assert.equal(api.emailDelay(email, nextProofRequest), 999);
    assert.equal(nextProofRequest[email], 1222);

    // Put the real current time back.
    Session.changeCurrentTime(currentTime);
    resolve();
  });
});
