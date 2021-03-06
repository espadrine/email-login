"use strict";

var crypto = require('crypto');
if (this.Promise === undefined) {
  this.Promise = require('promise');
}
var FsDb = require('./db/fs.js');
var Session = require('./session.js');
var Account = require('./account.js');
var NotFoundError = require('./db/not-found-error.js');

var PROOF_LIFESPAN = 1800000; // ms = 30min

// db: either a String to specify the default database's directory location,
// or a constructor with the same format as specified in src/db.js.
// options:
// - renewalPeriod: period in milliseconds between session token creation
//   and it being renewed for security purposes. Defaults to 0 (no renewal).
//   Note that this is unrelated to the session lifetime;
//   the session will still die after SESSION_LIFESPAN.
function Registry(db, options) {
  options = options || {};
  if (typeof db === 'string') {
    this.db = new FsDb({dir: db});
  } else {
    this.db = db;
  }
  this.renewalPeriod = (options.renewalPeriod !== undefined)?
    options.renewalPeriod: 0;
}

Registry.prototype = {
  // The memory contains the absolute truth.
  // This also loads the associated account if found.
  // id: base64url session identifier
  // cb(error, session)
  load: function(id, cb) {
    cb = cb || function(){};
    var self = this;
    self.db.readSession(id, function(err, session) {
      if (err != null) { return cb(err); }
      if (session.emailVerified()) {
        self.db.readAccount('email', session.email, function(err, account) {
          session.account = account;
          cb(null, session);
        });
      } else {
        cb(null, session);
      }
    });
  },
  // email: account identifier, cb(error, Account)
  loadAccount: function(email, cb) {
    cb = cb || function(){};
    this.db.readAccount('email', email, cb);
  },
  // Destroy the session.
  // id: base64url session identifier
  // cb(error)
  logout: function(id, cb) {
    cb = cb || function(){};
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      if (session.account != null) {
        session.account.rmSession(id);
        // Remember to save the modifications made to the account.
        var saveAccount = true;
      }
      self.db.deleteSession(id, function(err) {
        if (err != null) { return cb(err); }
        if (saveAccount) {
          self.db.updateAccount(session.account, cb);
        } else { cb(null); }
      });
    });
  },
  // Destroy the account and all associated sessions.
  // email: string
  // cb(error)
  rmAccount: function(email, cb) {
    cb = cb || function(){};
    var self = this;
    self.loadAccount(email, function(err, account) {
      if (err != null) { return cb(err); }
      var sessionDeleters = account.sessionIds.map(function(sessionId) {
        return new Promise(function(resolve, reject) {
          self.db.deleteSession(sessionId, function(err) {
            if (err != null) { return reject(err); }
            resolve();
          });
        });
      });
      Promise.all(sessionDeleters).then(function() {
        self.db.deleteAccount('email', email, function(err) {
          if (err != null) { return cb(err); }
          cb(null);
        });
      }).catch(function(err) {
        cb(err);
      });
    });
  },
  // Store the session data in the drive registry.
  // Also saves the session's account, if any.
  // session: a Session, cb: function(err).
  save: function(session, cb) {
    cb = cb || function(){};
    var self = this;
    self.db.updateSession(session, function(err) {
      if (err != null) { return cb(err); }
      if (session.account != null) {
        self.db.updateAccount(session.account, cb);
      } else { cb(null); }
    });
  },
  // Add the session to the account, save the session and the account.
  // email, session, cb: function(err).
  addSessionToAccount: function(email, session, cb) {
    var self = this;
    self.loadAccount(email, function(err, account) {
      if (err != null) {
        var accountIsInexistent = (err instanceof NotFoundError);
        if (accountIsInexistent) {
          account = new Account('email', email, []);
          account.addSession(session);
          session.account = account;
          self.db.createAccount(account, function(err, account) {
            if (err != null) { cb(err); return; }
            self.db.updateSession(session, cb);
          });
          return;
        } else {
          return cb(err);
        }
      }
      account.addSession(session);
      // save() will save the account.
      session.account = account;
      self.save(session, cb);
    });
  },
  // cb(error)
  // Run once every time we start the software.
  setup: function(cb) {
    cb = cb || function(){};
    this.db.setup(cb);
  },
  // cb(err, secret, session)
  login: function(cb) {
    var session = Session.newSession();
    session.renew = Session.currentTime() + this.renewalPeriod;
    try {
      var secret = session.setToken();
    } catch(e) { return cb(e); }
    this.db.createSession(session, function(err) { cb(err, secret, session); });
  },
  // Create a claim for an email.
  // id: Session id.
  // cb(err, session: Session | undefined)
  claim: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      session.addClaim('email', email);
      self.save(session, function(err) { cb(err, session); });
    });
  },
  // Create a proof for a specific email.
  // cb(err, emailSecret, emailSession)
  proof: function(email, cb) {
    var session = Session.newSession();
    try {
      var secret = session.setToken();
    } catch(e) { return cb(e); }
    var claim = session.addClaim('email', email);
    session.proveClaim(claim);
    session.expire = Session.currentTime() + PROOF_LIFESPAN;
    this.db.createSession(session, function(err) { cb(err, secret, session); });
  },
  // Force the session with a given id to learn
  // that it has proved access to email.
  // cb(err, session: Session | undefined)
  confirmEmailProved: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      var claim = session.addClaim('email', email);
      session.proveClaim(claim);
      session.lastAuth = Session.currentTime();
      // Saving is done inside.
      self.addSessionToAccount(email, session, function(err) {
        if (err != null) { return cb(err); }
        self.load(session.id, cb);
      });
    });
  },
  // Set data about a given account, so that account.data is that.
  // email: String of email address.
  // data: JSON-serializable object.
  // cb: function(err)
  setAccountData: function(email, data, cb) {
    var self = this;
    self.loadAccount(email, function(err, account) {
      if (err != null) { return cb(err); }
      account.data = data;
      self.db.updateAccount(account, cb);
    });
  },
  // Verify a token in base64 by comparing its hash to the registry's.
  // cb(err, authenticated, session, secret)
  // authenticated should always be either true or false.
  // secret is either undefined or needs to be stored client-side.
  auth: function(id, token, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) {
        var accountIsInexistent = (err instanceof NotFoundError);
        if (accountIsInexistent) {
          return cb(null, false, session);
        } else {
          return cb(err, false);
        }
      }
      try {
        var tokenBuf = new Buffer(token, 'base64');
        // Hash the token.
        var hash = crypto.createHash(session.hash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest();
      } catch(e) {
        return cb(e, false);
      }
      var now = Session.currentTime();
      var isExpired = (session.expire <= now);
      if (isExpired) {
        self.logout(session.id, function(err) { cb(null, false, session); });
        return;
      }
      var sessionToken = Session.bufferFromBase64url(session.token);
      // This comparison is made constant-time to prevent a timing attack.
      var authenticated = constEq(hashedToken, sessionToken);
      if (authenticated) {
        var shouldRenew = (self.renewalPeriod !== 0)
          && (session.renew <= now);
        if (shouldRenew) {
          session.lastAuth = now;
          session.renew = now + self.renewalPeriod;
          try {
            var secret = session.setToken();
          } catch(e) { cb(e, false); return; }
          self.db.updateSession(session, function(err) {
            if (err != null) { cb(err, false); return; }
            cb(null, true, session, secret);
          });
          return;
        } else {
          cb(null, true, session);
        }
      } else {
        cb(null, false, session);
      }
    });
  },
};

// Constant-time buffer equality.
function constEq(a, b) {
  if (a.length !== b.length) { return false; }
  var zero = 0;
  for (var i = 0; i < a.length; i++) {
    zero |= a[i] ^ b[i];
  }
  return (zero === 0);
}

exports.Session = Session;
exports.Registry = Registry;
exports.base64url = Session.base64url;
exports.bufferFromBase64url = Session.bufferFromBase64url;
// Exports for the purpose of tests.
exports.currentTime = Session.currentTime;
exports.changeCurrentTime = Session.changeCurrentTime;
exports.PROOF_LIFESPAN = PROOF_LIFESPAN;
