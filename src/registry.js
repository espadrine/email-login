"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

function Session(hash, token, id, createdAt, lastAuth, emailProved) {
  this.hash = hash;
  this.token = token;
  this.id = id;
  this.createdAt = createdAt || (+new Date());
  this.lastAuth = lastAuth || this.createdAt;
  this.emailProved = !!emailProved;
}

Session.prototype = {
  encode: function() {
    return JSON.stringify([this.hash, this.token, this.id,
        this.createdAt, this.lastAuth, this.emailProved]);
  }
};

function decodeSession(json) {
  var json = JSON.parse(json);
  return new Session(json[0], json[1], json[2], json[3], json[4], json[5]);
}

// Token class

function Token(email, blocked, loginTime, loginHash, loginToken) {
  this.email = email;
  this.blocked = blocked;
  this.loginTime = loginTime;
  this.loginHash = loginHash;
  this.loginToken = loginToken;
  this.sessions = [];
}

Token.prototype = {
  block: function() {
    this.blocked = false;
  },
  // Set the login token, return it as a buffer.
  // Warning: can throw.
  setLoginToken: function() {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand256 = crypto.randomBytes(32);
    hash.update(rand256);
    this.loginHash = alg;
    this.loginToken = hash.digest('base64');
    this.loginTime = +new Date();
    return rand256;
  },
  newSessionId: function() {
    var id = 0;
    // We assume that session ids increase with their indices.
    for (var i = 0; i < this.sessions.length; i++) {
      if (id === this.sessions[i].id) {
        id += 1;
      }
    }
    return id;
  },
  // Set the login token.
  // Returns {secret: Buffer, session: Session}
  // Warning: can throw.
  addSession: function() {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand256 = crypto.randomBytes(32);
    hash.update(rand256);
    var session = new Session(alg, hash.digest('base64'), this.newSessionId());
    this.sessions.push(session);
    return {
      session: session,
      secret: rand256,
    };
  },
  rmSession: function(i) {
    this.sessions.splice(i, 1);
  },
  getSession: function(id) {
    for (var i = 0; i < this.sessions.length; i++) {
      var session = this.sessions[i];
      if (session.id === id) { return session; }
    }
  },
  encodeSession: function() {
    var sessions = [];
    for (var i = 0; i < this.sessions.length; i++) {
      sessions.push(this.sessions[i].encode());
    }
    return sessions;
  },
  encode: function() {
    return JSON.stringify([
      this.email, this.blocked, this.loginTime, this.loginHash,
      this.loginToken, this.encodeSession()
    ]);
  }
};

// Registry primitives

function decodeToken(json) {
  var json = JSON.parse(json);
  return new Token(
    json[0],    // Email
    json[1],    // Blocked?
    json[2],    // Last login timestamp
    json[3],    // Last login hash type for token
    json[4],    // Last login token
    decodeSession(json[5])
  );
}

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
  this.data = {};
}

Registry.prototype = {
  // The memory contains the absolute truth.
  load: function(email, cb) {
    cb = cb || function(){};
    if (this.data[email] !== undefined) {
      cb(null, this.data[email]);
      return;
    }
    var encEmail = base64url(Buffer(email));
    var file = path.join(this.dir, encEmail);
    var data = this.data;
    fs.readFile(file, function(err, json) {
      if (err != null) { cb(err); return; }
      json = "" + json;
      try {
        data[email] = decodeToken(json);
        cb(null, data[email]);
      } catch(e) { cb(e); }
    });
  },
  // Store the email's token data in the drive registry.
  save: function(email, cb) {
    cb = cb || function(){};
    var encEmail = base64url(Buffer(email));
    var file = path.join(this.dir, encEmail);
    try {
      fs.writeFile(file, this.data[email].encode(), cb);
    } catch(e) { cb(e); }
  },
  mkdir: function(cb) {
    cb = cb || function(){};
    var dir = this.dir;
    fs.stat(dir, function(err, stats) {
      if (err == null) {
        cb();
      } else if (err.code === 'ENOENT') {
        fs.mkdir(dir, cb);
      } else { cb(err); }
    });
  },
  // cb(err, token)
  add: function(email, cb) {
    cb = cb || function(){};
    var token = new Token(
      email,    // Email
      false,    // Blocked?
      0,        // Last login timestamp
      '',       // Last login hash type for token
      '',       // Last login token
      []        // Sessions
    );
    this.data[email] = token;
    this.save(email, function(err) { cb(err, token); });
  },
  // cb(err, token)
  loadOrAdd: function(email, cb) {
    var self = this;
    this.load(email, function(err, token) {
      if (err != null) {
        self.add(email, cb);
      } else {
        cb(null, token);
      }
    });
  },
  // Returns a secret `cb(err, rand256)`.
  login: function(email, cb) {
    var self = this;
    this.loadOrAdd(email, function(err, token) {
      if (err != null) { cb(err); return; }
      try {
        var rand256 = token.setLoginToken();
        self.save(email, function(err) {
          if (err != null) { cb(err); return; }
          cb(null, rand256);
        });
      } catch(e) { cb(e); }
    });
  },
  // Returns a secret `cb(err, {secret: Buffer, session: Session})`.
  newSession: function(email, cb) {
    var self = this;
    this.loadOrAdd(email, function(err, token) {
      if (err != null) { cb(err); return; }
      try {
        var session = token.addSession();
        self.save(email, function(err) {
          if (err != null) { cb(err); return; }
          cb(null, session);
        });
      } catch(e) { cb(e); }
    });
  },
  // Block the email from authenticating.
  // cb(err)
  block: function(email, cb) {
    var self = this;
    this.loadOrAdd(email, function(err, token) {
      if (err != null) { cb(err); return; }
      token.blocked = true;
      self.save(email, cb);
    });
  },
  // Verify a confirmation token by comparing its hash to the registry's.
  confirm: function(email, token, cb) {
    var self = this;
    var tokenBuf = new Buffer(token, 'base64');
    this.loadOrAdd(email, function(err, storedToken) {
      if (err != null) { cb(err); return; }
      // Deny blocked emails.
      if (storedToken.blocked) { cb(null, false); return; }
      try {
        // Hash the token.
        var hash = crypto.createHash(storedToken.loginHash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
        cb(null, hashedToken === storedToken.loginToken);
      } catch(e) { cb(e); }
    });
  },
  // Verify a token by comparing its hash to the registry's.
  // cb(err, authorized, email verified)
  auth: function(email, sessionId, token, cb) {
    var self = this;
    var tokenBuf = new Buffer(token, 'base64');
    this.loadOrAdd(email, function(err, storedToken) {
      if (err != null) { cb(err); return; }
      // Deny blocked emails.
      if (storedToken.blocked) { cb(null, false); return; }
      try {
        // Hash the token.
        var session = storedToken.getSession(sessionId);
        if (!session) { return cb(Error('Session not found')); }
        var hash = crypto.createHash(session.hash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
        cb(null, hashedToken === session.token, session.emailProved);
      } catch(e) { cb(e); }
    });
  },
};

exports.Token = Token;
exports.Registry = Registry;
exports.base64url = base64url;
exports.bufferFromBase64url = bufferFromBase64url;
