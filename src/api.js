"use strict";

var registry = require('./registry.js');
var Mailer = require('./mailer.js');
var Promise = require('promise');
var Session = require('./session.js');

var Registry = registry.Registry;
var base64url = registry.base64url;
var bufferFromBase64url = registry.bufferFromBase64url;

var proofError = 'We could not prove email ownership';
var emailRateLimitError = 'Too many requests for email proof';
var invalidEmailError = 'The email address is clearly invalid';
var confirmError = 'We could not confirm email ownership';
var accountError = 'We could not fetch an account';
var logoutError = 'We could not log you out';

// options:
// - mailer: object, see mailer.js
// - db: path to storage point as a string, or constructor, see db.js.
// - emailRateLimit: true by default.
// cb: function(err)
function Api(options, cb) {
  this.registry = new Registry(options.db);
  this.mailer = new Mailer(options.mailer);
  this.registry.setup(cb);
  this.emailRateLimit = (options.emailRateLimit === false)? false: true;
  this.nextProofRequest = Object.create(null);
}

Api.prototype = {
  // cb(error, cookieToken, session)
  login: function(cb) {
    this.registry.login(function(err, secret, session) {
      if (err != null) { return cb(err); }
      var cookieToken = encodeToken(session.id, secret);
      cb(null, cookieToken, session);
    });
  },

  emailRateLimit: true,
  // Map from email to minimum timestamp of next email proof request.
  // FIXME: LRU-evict older mail servers? Might lead to circumvention.
  nextProofRequest: Object.create(null),

  // Return the domain for an email (eg, tt@example.com → @example.com).
  emailDomain: function(email) {
    var domainStart = email.lastIndexOf('@');
    // If there is no @, domainStart is -1.
    // We also don't want emails that don't have anything before the @
    // (which would mean domainStart is 0).
    if (domainStart < 1) { return; }
    return email.slice(domainStart);
  },

  // Ensure we keep a 1s delay between each email to a mail server.
  // Returns the delay to apply in milliseconds.
  emailDelay: function() {
    var mailEmissionLapse = 1000;
    // delay in milliseconds.
    var delay = 0;
    if (this.emailRateLimit) {
      if (this.nextProofRequest[emailDomain] !== undefined) {
        if (now < this.nextProofRequest[emailDomain] + mailEmissionLapse) {
          // We wouldn't respect the lapse if we sent it now.
          this.nextProofRequest[emailDomain] += mailEmissionLapse;
          delay = this.nextProofRequest[emailDomain];
        }
      } else {
        this.nextProofRequest[emailDomain] = now + mailEmissionLapse;
      }
    }
    return delay;
  },

  // options:
  // - token (the cookieToken as a string)
  // - email
  // - subject: function(name)
  // - textMessage: function(emailToken, confirmUrl)
  //   (Use emailToken in your confirmation URL. confirmUrl is optional and
  //   meant to be function(emailToken).)
  //   to be the start of an URL including scheme + domain + port.)
  // - htmlMessage: function(emailToken, confirmUrl)
  //   (Use emailToken in your confirmation URL. confirmUrl is optional and
  //   meant to be function(emailToken).)
  // - name (optional): used in the default subject.
  // - confirmUrl (optional): function(emailToken).
  // cb: function(err, emailToken)
  proveEmail: function(options, cb) {
    var cookieToken = options.token;
    var email = options.email;
    var subject = options.subject || defaultSubject;
    var textMessage = options.textMessage || defaultTextMessage;
    var htmlMessage = options.htmlMessage || defaultHtmlMessage;
    var self = this;

    var emailDomain = this.emailDomain(email);
    if (emailDomain === undefined) {
      cb(Error(invalidEmailError));
      return;
    }
    var now = Session.currentTime();

    // delay in milliseconds.
    var delay = this.emailDelay();
    if (delay > 1000 * 60 * 2) {
      // We'd delay for more than 2 minutes (120 delayed mails).
      cb(Error(emailRateLimitError));
      return;
    }

    self.registry.proof(email, function(err, emailSecret, emailSession) {
      if (err != null) { return cb(err); }
      if (emailSecret == null) { return cb(Error(proofError)); }
      var emailToken = encodeToken(emailSession.id, emailSecret);

      setTimeout(function() {
        self.mailer.send({
          to: email,
          subject: subject(options.name),
          text: textMessage(emailToken, options.confirmUrl),
          html: htmlMessage(emailToken, options.confirmUrl),
        }, function(err) { if (err != null) { console.error(err); } });
      }, delay);

      cb(null, emailToken);
    });
  },

  // cb: function(err, cookieToken, session, oldSession)
  // The returned token is undefined if the confirmation failed.
  // The sessions can be undefined.
  confirmEmail: function(cookieToken, emailToken, cb) {
    try {
      var elements = decodeToken(emailToken);
    } catch(e) { return cb(Error(confirmError)); }
    var emailId = elements.id;
    var emailSecret = elements.token;
    if (emailId == null || emailSecret == null) {
      return cb(Error(confirmError));
    }

    var self = this;
    self.registry.auth(emailId, emailSecret, function(err, confirmed, session) {
      if (err != null || !confirmed) {
        if (session !== undefined) {
          // Refresh the session.
          self.registry.load(session.id, function(err, session) {
            if (err != null) { return cb(err); }
            cb(null, undefined, session, session);
          });
        } else { cb(null); }
        return;
      }

      if (cookieToken === undefined) {
        // We received a confirmation from an unknown device.
        self.login(function(err, newToken, newSession) {
          if (err != null) { return cb(err); }
          self.registry.confirmEmailProved(newSession.id, session.email,
          function(err, newSession) {
            if (err != null) { return cb(err); }
            // Burn the emailSession.
            // Whether burning the emailSession succeeded is irrelevant, as we only
            // do it for the memory and cleanliness.
            self.registry.logout(emailId, function(err) {
              cb(null, newToken, newSession, session);
            });
          });
        });

      } else {
        var elements = decodeToken(cookieToken);
        var id = elements.id;
        self.registry.confirmEmailProved(id, session.email,
        function(err, newSession) {
          if (err != null) { return cb(err); }
          // Burn the emailSession.
          self.registry.logout(emailId, function(err) {
            cb(null, cookieToken, newSession, session);
          });
        });
      }
    });
  },

  // cb: function(err, authenticated, session)
  // If authentication failed, session might be undefined.
  authenticate: function(cookieToken, cb) {
    // Any type of invalidity translates to a refusal to authenticate.
    if (!cookieToken) {
      return cb(null, false);
    }
    try {
      var elements = decodeToken(cookieToken);
    } catch(e) { return cb(null, false); }
    var id = elements.id;
    var token = elements.token;
    if (id == null || token == null) {
      return cb(null, false);
    }

    this.registry.auth(id, token, cb);
  },

  // id: base64url session identifier
  // cb(error, session)
  session: function(id, cb) {
    this.registry.load(id, cb);
  },

  // email: account identifier
  // cb: function(err, account)
  // An account is an object with the following fields (not to be confused with
  // registry.js' Account):
  // - email
  // - sessions: list of Session objects.
  account: function(email, cb) {
    var self = this;
    if (email == null) { return cb(Error(accountError)); }
    self.registry.loadAccount(email, function(err, account) {
      if (err != null) { return cb(err); }
      var sessionLoaders = [];
      account.sessionIds.forEach(function(sessionId) {
        sessionLoaders.push(new Promise(function(resolve, reject) {
          self.registry.load(sessionId, function(err, session) {
            if (err != null) { return reject(err); }
            resolve(session);
          });
        }));
      });
      Promise.all(sessionLoaders).then(function(sessions) {
        cb(null, {
          email: email,
          sessions: sessions,
        });
      }).catch(function(err) {
        cb(err);
      });
    });
  },

  // cb: function(error)
  // Remove the session associated with the cookieToken.
  logout: function(cookieToken, cb) {
    if (!cookieToken) {
      return cb(null);
    }
    try {
      var elements = decodeToken(cookieToken);
    } catch(e) { return cb(Error(logoutError)); }
    var id = elements.id;
    var token = elements.token;
    if (id == null || token == null) {
      return cb(Error(logoutError));
    }

    this.registry.logout(id, cb);
  },

  // cb: function(error)
  // Remove the session associated with the sessionId.
  deleteSession: function(sessionId, cb) {
    this.registry.logout(sessionId, cb);
  },

  // cb: function(error)
  // Delete all sessions and information associated to an email.
  deleteAccount: function(email, cb) {
    this.registry.rmAccount(email, cb);
  },
};

// Primitives

// Return {id: base64url, token: base64, version: int}
function decodeToken(base64) {
  var elements = base64.split('.');
  var version = +elements[0];
  var id = elements[1];
  var tokenBase64url = elements[2];
  return {
    id: id,
    token: tokenBase64url.replace(/\-/g, '+').replace(/_/g, '/'),
    version: version,
  };
}

// id: base64url, secret: Buffer, version: int.
// The link token is
// <version>.<id as base64url>.<base64url of the secret>
function encodeToken(id, secret, version) {
  version = version || 1;
  return version + '.' + id + '.' + base64url(secret);
}

function defaultSubject(name) {
  return '[' + name + '] Identity verification'
}

function defaultConfirmUrl(emailToken) {
  return 'https://127.0.0.1/login?token=' + emailToken;
}

function defaultTextMessage(emailToken, confirmUrl) {
  confirmUrl = confirmUrl || defaultConfirmUrl;
  return 'Hi!\n\n' +
    'You can confirm that you own this email address by clicking ' +
    'on this link:\n\n' + confirmUrl(emailToken) + '\n\n' +
    'Please point your browser to that URL and you will be good to go!\n\n' +
    'Cheers!';
}

function defaultHtmlMessage(emailToken, confirmUrl) {
  confirmUrl = confirmUrl || defaultConfirmUrl;
  var link = escapeHtml(confirmUrl(emailToken));
  return '<p>Hi!</p>\n\n' +
    '<p>You can confirm that you own this email address by clicking ' +
    '<a href="' + link + '">' + 'here</a>.</p>' +
    '<p>Cheers!</p>';
}

function escapeHtml(text) {
  return text.replace(/\&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = Api;
module.exports.encodeToken = encodeToken;
module.exports.decodeToken = decodeToken;
