"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
if (this.Promise === undefined) {
  this.Promise = require('promise');
}
var DirectoryDb = require('./db/fs.js');
var Session = require('./session.js');
var Account = require('./account.js');
var NotFoundError = require('./db/not-found-error.js');

var PROOF_LIFESPAN = 1800000; // ms = 30min

// db: either a String to specify the default database's directory location,
// or a constructor with the same format as specified in src/db.js.
function Registry(db) {
  if (Object(db) instanceof String) {
    this.db = new DirectoryDb({dir: db});
  } else {
    this.db = new db();
  }
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
      var sessionDeleters = [];
      account.sessionIds.forEach(function(sessionId) {
        sessionDeleters.push(new Promise(function(resolve, reject) {
          self.db.deleteSession(sessionId, function(err) {
            if (err != null) { return reject(err); }
            resolve();
          });
        }));
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
    try {
      var secret = session.setToken();
    } catch(e) { return cb(e); }
    this.save(session, function(err) { cb(err, secret, session); });
  },
  // Create a claim for an email.
  // id: Session id.
  // cb(err, session: Session | undefined)
  claim: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      var claim = session.addClaim('email', email);
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
    this.save(session, function(err) { cb(err, secret, session); });
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
      // Saving is done inside.
      self.addSessionToAccount(email, session, function(err) {
        if (err != null) { return cb(err); }
        self.load(session.id, cb);
      });
    });
  },
  // Verify a token in base64 by comparing its hash to the registry's.
  // cb(err, authenticated, session)
  // authenticated should always be either true or false.
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
      var inTime = (now < session.expire);
      var sessionToken = Session.bufferFromBase64url(session.token);
      // This comparison is made constant-time to prevent a timing attack.
      var matching = constEq(hashedToken, sessionToken);
      var authenticated = (inTime && matching);
      if (authenticated) {
        session.lastAuth = now;
      }
      if (!inTime) {
        self.logout(session.id, function(err) {
          cb(null, authenticated, session);
        });
      } else {
        self.save(session, function(err) { cb(null, authenticated, session); });
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
