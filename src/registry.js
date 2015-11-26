"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var Promise = require('promise');
var DirectoryDb = require('./db.js');
var Session = require('./session.js');
var Account = require('./account.js');

var PROOF_LIFESPAN = 3600000; // ms = 1h

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
        self.db.readAccount(session.email, function(err, account) {
          session.account = account;
          cb(err, session);
        });
      } else {
        cb(null, session);
      }
    });
  },
  // email: account identifier, cb(error, Account)
  loadAccount: function(email, cb) {
    cb = cb || function(){};
    this.db.readAccount(email, cb);
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
        self.db.deleteAccount(email, function(err) {
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
  // session: a Session.
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
  // email, session, cb: function(err)
  addSessionToAccount: function(email, session, cb) {
    var self = this;
    self.loadAccount(email, function(err, account) {
      if (err != null) {
        var accountIsInexistent = (err.code === 'ENOENT');
        if (accountIsInexistent) {
          account = new Account(email, []);
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
  // cb(err, secret, session)
  proof: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      try {
        var secret = session.setProof(email);
      } catch(e) { return cb(e); }
      self.save(session, function(err) { cb(err, secret, session); });
    });
  },
  // cb(err)
  manualConfirmEmail: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      session.email = email;
      session.proofHash = '';
      session.proofToken = '';
      session.proofCreatedAt = 0;
      // Saving is done inside.
      self.addSessionToAccount(email, session, cb);
    });
  },
  // Verify an email proof token in base64 by comparing it to the registry's.
  // cb(error, validity, session)
  confirm: function(id, token, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      try {
        var tokenBuf = new Buffer(token, 'base64');
      } catch(e) { return cb(e); }
      // Hash the token.
      if (!session.proofHash) {
        // The proof hash is inexistent, so the token is invalid.
        return cb(null, false, session);
      }
      try {
        var hash = crypto.createHash(session.proofHash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
      } catch(e) { return cb(e); }
      // Check the validity.
      var inTime = ((Session.currentTime() - session.proofCreatedAt)
        < PROOF_LIFESPAN);
      var valid = (hashedToken === session.proofToken);
      // valid should be last, just in case short-circuit eval leaks data.
      var confirmed = inTime && valid;
      if (!confirmed) {
        return cb(null, false, session);
      }
      // The token is confirmed.
      session.proofHash = '';
      session.proofToken = '';
      session.proofCreatedAt = 0;
      // Saving is done inside.
      self.addSessionToAccount(session.email, session, function(err) {
        cb(err, true, session);
      });
    });
  },
  // Verify a token in base64 by comparing its hash to the registry's.
  // cb(err, authenticated, session)
  // authenticated should always be either true or false.
  auth: function(id, token, cb) {
    var self = this;
    this.load(id, function(err, session) {
      if (err != null) { return cb(err, false); }
      try {
        var tokenBuf = new Buffer(token, 'base64');
        // Hash the token.
        var hash = crypto.createHash(session.hash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
      } catch(e) {
        return cb(e, false);
      }
      var authenticated = (hashedToken === session.token);
      if (authenticated) {
        session.lastAuth = Session.currentTime();
      }
      cb(err, authenticated, session);
    });
  },
};


exports.Session = Session;
exports.Registry = Registry;
exports.base64url = Session.base64url;
exports.bufferFromBase64url = Session.bufferFromBase64url;
// Exports for the purpose of tests.
exports.currentTime = Session.currentTime;
exports.changeCurrentTime = Session.changeCurrentTime;
exports.PROOF_LIFESPAN = PROOF_LIFESPAN;
