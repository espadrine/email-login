"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// Sessions identify a device. They have an id (uuid-like number)
// and a secret. They can prove that they are linked to an email.
// To perform this proof, they need a temporary secret.

function Session(id, hash, token, createdAt, lastAuth, email,
    proofHash, proofToken, proofCreatedAt) {
  this.id = '' + id;
  this.hash = '' + hash;
  this.token = '' + token;
  this.createdAt = +createdAt || (+new Date());
  this.lastAuth = +lastAuth || 0;
  // If there is an email and no proof, the email has been verified.
  this.email = '' + email;
  this.proofHash = '' + proofHash;
  this.proofToken = '' + proofToken;
  this.proofCreatedAt = +proofCreatedAt;
}

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
    this.proofCreatedAt = (+new Date());
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
    '',    // proofHash
    '',    // proofToken
    0      // proofCreatedAt
  );
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
  this.data = {};
}

Registry.prototype = {
  // The memory contains the absolute truth.
  // id: base64url session identifier
  // cb(error, session)
  load: function(id, cb) {
    cb = cb || function(){};
    if (this.data[id] !== undefined) {
      cb(null, this.data[id]);
      return;
    }
    var file = path.join(this.dir, 'session', id);
    var data = this.data;
    fs.readFile(file, function(err, json) {
      if (err != null) { cb(err); return; }
      json = "" + json;
      try {
        data[id] = decodeSession(json);
        cb(null, data[id]);
      } catch(e) { cb(e); }
    });
  },
  // Store the session data in the drive registry.
  // id: base64url session identifier.
  save: function(id, cb) {
    cb = cb || function(){};
    var file = path.join(this.dir, 'session', id);
    try {
      fs.writeFile(file, this.data[id].encode(), cb);
    } catch(e) { cb(e); }
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
  mkdir: function(cb) {
    cb = cb || function(){};
    var self = this;
    self.mkdirname(self.dir, function(err) {
      if (err != null) { return cb(err); }
      self.mkdirname(path.join(self.dir, 'session'), cb);
    });
  },
  // cb(err, secret, session)
  login: function(cb) {
    var session = newSession();
    try {
      var secret = session.setToken();
    } catch(e) { return cb(e); }
    this.data[session.id] = session;
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
      self.save(id, function(err) { cb(err); });
    });
  },
  // Verify an email proof token in base64 by comparing it to the registry's.
  // cb(error, validity, session)
  confirm: function(id, token, cb) {
    var self = this;
    this.load(id, function(err, session) {
      if (err != null) { return cb(err); }
      try {
        var tokenBuf = new Buffer(token, 'base64');
        // Hash the token.
        var hash = crypto.createHash(session.proofHash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
        var valid = (hashedToken === session.proofToken);
        if (valid) {
          session.proofHash = '';
          session.proofToken = '';
          session.proofCreatedAt = 0;
          self.save(id, function(err) { cb(err, true, session); });
        } else {
          cb(null, false, session);
        }
      } catch(e) { cb(e); }
    });
  },
  // Verify a token in base64 by comparing its hash to the registry's.
  // cb(err, authenticated, session)
  auth: function(id, token, cb) {
    var self = this;
    this.load(id, function(err, session) {
      if (err != null) { cb(err); return; }
      try {
        var tokenBuf = new Buffer(token, 'base64');
        // Hash the token.
        var hash = crypto.createHash(session.hash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
        var authenticated = (hashedToken === session.token);
        if (authenticated) {
          session.lastAuth = (+new Date());
        }
        cb(null, authenticated, session);
      } catch(e) { cb(e); }
    });
  },
};

exports.Session = Session;
exports.Registry = Registry;
exports.base64url = base64url;
exports.bufferFromBase64url = bufferFromBase64url;
