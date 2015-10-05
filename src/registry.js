"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var Promise = require('promise');

// Sessions identify a device. They have an id (uuid-like number)
// and a secret. They can prove that they are linked to an email.
// To perform this proof, they need a temporary secret.

function Session(id, hash, token, createdAt, lastAuth, email,
    proofCreatedAt, proofHash, proofToken) {
  this.id = '' + id;
  this.hash = '' + hash;
  this.token = '' + token;
  this.createdAt = +createdAt || currentTime();
  this.lastAuth = +lastAuth || 0;
  // If there is an email and no proof, the email has been verified.
  this.email = '' + email;
  this.proofCreatedAt = +proofCreatedAt;
  this.proofHash = '' + proofHash;
  this.proofToken = '' + proofToken;
}

var PROOF_LIFESPAN = 3600000; // ms = 1h

Session.prototype = {
  // Set the token, return it as a buffer.
  // Warning: can throw.
  setToken: function() {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand256 = crypto.randomBytes(32);
    hash.update(rand256);
    this.hash = alg;
    this.token = hash.digest('base64');
    return rand256;
  },
  // Set the proof, return it as a buffer.
  // Warning: can throw.
  setProof: function(email) {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand256 = crypto.randomBytes(32);
    hash.update(rand256);
    this.proofHash = alg;
    this.proofToken = hash.digest('base64');
    this.proofCreatedAt = currentTime();
    this.email = email;
    return rand256;
  },
  emailVerified: function() {
    return (!!this.email) && (this.proofCreatedAt === 0);
  },
  encode: function() {
    return JSON.stringify([this.id, this.hash, this.token,
        this.createdAt, this.lastAuth, this.email,
        this.proofCreatedAt, this.proofHash, this.proofToken]);
  }
};

function decodeSession(json) {
  var json = JSON.parse(json);
  return new Session(json[0], json[1], json[2], json[3], json[4], json[5],
      json[6], json[7], json[8]);
}

function newSession() {
  // An id is always a sha256 base64url random string.
  // Think of it as a stronger UUID.
  var hash = crypto.createHash('sha256');
  var rand256 = crypto.randomBytes(32);
  hash.update(rand256);
  var id = base64url(hash.digest('base64'));
  return new Session(
    id,
    '',    // hash
    '',    // token
    null,  // set the creation date
    null,  // now is the last auth
    '',    // email
    0,     // proofCreatedAt
    '',    // proofHash
    ''     // proofToken
  );
}

function Account(email, sessionIds) {
  this.email = email;
  this.sessionIds = sessionIds || []; // list of base64url session identifiers.
}

Account.prototype = {
  addSession: function(session) {
    this.sessionIds.push(session.id);
  },
  rmSession: function(sessionId) {
    var rmid = this.sessionIds.indexOf(sessionId);
    this.sessionIds.splice(rmid, 1);
  },
  encode: function() {
    return JSON.stringify([this.email, this.sessionIds]);
  }
};

function decodeAccount(json) {
  var json = JSON.parse(json);
  return new Account(json[0], json[1]);
}

// Registry primitives

function base64url(buf) {
  if (typeof buf === 'string') { buf = new Buffer(buf); }
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=/g, '');
}

function bufferFromBase64url(string) {
  string = string.replace(/\-/g, '+').replace(/_/g, '/');
  return Buffer(string, 'base64');
}

function Registry(dir) {
  this.dir = dir;
  this.sessions = {};  // map from base64url session identifier to Session.
  this.accounts = {};  // map from email to Account.
}

Registry.prototype = {
  // The memory contains the absolute truth.
  // This also loads the associated account if found.
  // id: base64url session identifier
  // cb(error, session)
  load: function(id, cb) {
    cb = cb || function(){};
    var self = this;
    if (self.sessions[id] !== undefined) {
      cb(null, self.sessions[id]);
      return;
    }
    var file = path.join(self.dir, 'session', id);
    var sessions = self.sessions;
    fs.readFile(file, function(err, json) {
      if (err != null) { cb(err); return; }
      json = "" + json;
      try {
        sessions[id] = decodeSession(json);
      } catch(e) { return cb(e); }
      var session = sessions[id];
      if (session.emailVerified()) {
        self.loadAccount(session.email, function(err) {
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
    if (this.accounts[email] !== undefined) {
      cb(null, this.accounts[email]);
      return;
    }
    var eb64 = base64url(email);
    var file = path.join(this.dir, 'account', eb64);
    var accounts = this.accounts;
    fs.readFile(file, function(err, json) {
      if (err != null) { cb(err); return; }
      json = "" + json;
      try {
        accounts[email] = decodeAccount(json);
      } catch(e) { return cb(e); }
      cb(null, accounts[email]);
    });
  },
  // Destroy the session.
  // id: base64url session identifier
  // cb(error)
  logout: function(id, cb) {
    cb = cb || function(){};
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      var file = path.join(self.dir, 'session', id);
      var email = session.email;
      var isEmailVerified = session.emailVerified();
      // Some sessions don't have emails.
      if (self.accounts[email] !== undefined) {
        self.accounts[email].rmSession(id);
      }
      delete self.sessions[id];
      fs.unlink(file, function(err) {
        if (err != null) { cb(err); return; }
        if (isEmailVerified) {
          self.saveAccount(email, cb);
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
          // The session data is stored on memory and on file.
          var file = path.join(self.dir, 'session', sessionId);
          fs.unlink(file, function(err) {
            if (err != null) { return reject(e); }
            delete self.sessions[sessionId];
            resolve();
          });
        }));
      });
      Promise.all(sessionDeleters).then(function() {
        // Now, we delete the account on memory and on file.
        var eb64 = base64url(email);
        var file = path.join(self.dir, 'account', eb64);
        fs.unlink(file, function(err) {
          if (err != null) { return cb(e); }
          delete self.accounts[email];
          cb(null);
        });
      }).catch(function(err) {
        cb(err);
      });
    });
  },
  // Store the session data in the drive registry.
  // id: base64url session identifier.
  save: function(id, cb) {
    cb = cb || function(){};
    var self = this;
    var file = path.join(self.dir, 'session', id);
    var session = self.sessions[id];
    fs.writeFile(file, session.encode(), function(err) {
      if (err != null) { cb(err); return; }
      if (session.emailVerified()) {
        self.saveAccount(session.email, cb);
      } else { cb(null); }
    });
  },
  // Store the account in the drive registry.
  // email, cb: function(err).
  saveAccount: function(email, cb) {
    var eb64 = base64url(email);
    var accf = path.join(this.dir, 'account', eb64);
    var account = this.accounts[email];
    if (account == null) {
      return cb(new Error('Cannot save inexistent account'));
    }
    try {
      var encodedFilename = account.encode();
    } catch(e) {
      return cb(e);
    }
    fs.writeFile(accf, encodedFilename, cb);
  },
  addSessionToAccount: function(email, session) {
    if (this.accounts[email] === undefined) {
      this.accounts[email] = new Account(email, []);
    }
    this.accounts[email].addSession(session);
  },
  // cb(error)
  mkdirname: function(name, cb) {
    fs.stat(name, function(err, stats) {
      if (err == null) {
        cb();
      } else if (err.code === 'ENOENT') {
        fs.mkdir(name, cb);
      } else { cb(err); }
    });
  },
  // cb(error)
  // Run once every time we start the software.
  setup: function(cb) {
    cb = cb || function(){};
    var self = this;
    self.mkdirname(self.dir, function(err) {
      if (err != null) { return cb(err); }
      self.mkdirname(path.join(self.dir, 'session'), function(err) {
        if (err != null) { return cb(err); }
        self.mkdirname(path.join(self.dir, 'account'), cb);
      });
    });
  },
  // cb(err, secret, session)
  login: function(cb) {
    var session = newSession();
    try {
      var secret = session.setToken();
    } catch(e) { return cb(e); }
    this.sessions[session.id] = session;
    this.save(session.id, function(err) { cb(err, secret, session); });
  },
  // cb(err, secret, session)
  proof: function(id, email, cb) {
    var self = this;
    self.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      try {
        var secret = session.setProof(email);
      } catch(e) { return cb(e); }
      self.save(id, function(err) { cb(err, secret, session); });
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
      self.addSessionToAccount(email, session);
      self.save(id, function(err) { cb(err); });
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
        return cb(new Error('Cannot confirm this token'));
      }
      try {
        var hash = crypto.createHash(session.proofHash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
      } catch(e) { return cb(e); }
      // Check the validity.
      var inTime = (currentTime() - session.proofCreatedAt) < PROOF_LIFESPAN;
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
      self.addSessionToAccount(session.email, session);
      self.save(id, function(err) {
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
        session.lastAuth = currentTime();
      }
      cb(err, authenticated, session);
    });
  },
};


// Test helper functions

// Return a timestamp in milliseconds.
function currentTime() {
  return +(new Date());
}

function changeCurrentTime(f) { currentTime = f; }

exports.Session = Session;
exports.Registry = Registry;
exports.base64url = base64url;
exports.bufferFromBase64url = bufferFromBase64url;
// Exports for the purpose of tests.
exports.currentTime = currentTime;
exports.changeCurrentTime = changeCurrentTime;
exports.PROOF_LIFESPAN = PROOF_LIFESPAN;
