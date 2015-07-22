var assert = require('assert');
var rimraf = require('rimraf');
var Api = require('../src/api.js');

var directory = __dirname + '/shadow';
var api;

var normalFlowTest = function(cb) {
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
              cb();
            });
          });
        });
      });
    });
  });
};

var wrongConfirmationTest = function(cb) {
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
        cb();
      });
    });
  });
};

var unknownDeviceConfirmationTest = function(cb) {
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
      function(err, newToken, newSession) {
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
        cb();
      });
    });
  });
};

var wrongDeviceConfirmationTest = function(cb) {
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
      api.login(function(err, otherToken, otherSession) {
        if (err != null) { throw err; }

        api.confirmEmail(otherToken, emailToken,
        function(err, newToken, newSession) {
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
          cb();
        });
      });
    });
  });
};

var test = function(cb) {
  normalFlowTest(function(err) {
    wrongConfirmationTest(function(err) {
      if (err != null) { throw err; }
      wrongDeviceConfirmationTest(function(err) {
        if (err != null) { throw err; }
        unknownDeviceConfirmationTest(cb);
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
