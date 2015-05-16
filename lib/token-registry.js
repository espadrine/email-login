"use strict";

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// Token class

function Token(email, blocked, loginIp, loginTime, loginHash, loginToken,
    time, hash, token) {
  this.email = email;
  this.blocked = blocked;
  this.loginIp = loginIp;
  this.loginTime = loginTime;
  this.loginHash = loginHash;
  this.loginToken = loginToken;
  this.time = time;
  this.hash = hash;
  this.token = token;
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
    var rand128 = crypto.randomBytes(16);
    hash.update(rand128);
    this.loginHash = alg;
    this.loginToken = hash.digest('base64');
    this.loginTime = +new Date();
    return rand128;
  },
  // Set the login token, return it as a buffer.
  // Warning: can throw.
  setToken: function() {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand128 = crypto.randomBytes(16);
    hash.update(rand128);
    this.hash = alg;
    this.token = hash.digest('base64');
    this.time = +new Date();
    return rand128;
  },
  encode: function() {
    return JSON.stringify([
      this.email, this.blocked, this.loginIp, this.loginTime, this.loginHash,
      this.loginToken, this.time, this.hash, this.token
    ]);
  }
};

// Registry primitives

function decodeToken(json) {
  var json = JSON.parse(json);
  return new Token(
    json[0],    // Email
    json[1],    // Blocked?
    json[2],    // Last login attempt IP
    json[3],    // Last login timestamp
    json[4],    // Last login hash type for token
    json[5],    // Last login token
    json[6],    // Token creation time
    json[7],    // Hash type for token
    json[8]     // Token
  );
}

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=/g, '');
}

function TokenRegistry(dir) {
  this.dir = dir;
  this.data = {};
}

TokenRegistry.prototype = {
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
  // cb(err, token)
  add: function(email, cb) {
    cb = cb || function(){};
    var token = new Token(
      email,    // Email
      false,    // Blocked?
      '',       // Last login attempt IP
      0,        // Last login timestamp
      '',       // Last login hash type for token
      '',       // Last login token
      0,        // Token creation time
      '',       // Hash type for token
      ''        // Token
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
  // Returns a secret `cb(err, rand128)`.
  login: function(email, cb) {
    var self = this;
    this.loadOrAdd(email, function(err, token) {
      if (err != null) { cb(err); return; }
      try {
        var rand128 = token.setLoginToken();
        self.save(email, function(err) {
          if (err != null) { cb(err); return; }
          cb(null, rand128);
        });
      } catch(e) { cb(e); }
    });
  },
  // Returns a secret `cb(err, rand128)`.
  reset: function(email, cb) {
    var self = this;
    this.loadOrAdd(email, function(err, token) {
      if (err != null) { cb(err); return; }
      try {
        var rand128 = token.setToken();
        self.save(email, function(err) {
          if (err != null) { cb(err); return; }
          cb(null, rand128);
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
  // Verify a token by comparing its hash to the registry's.
  loginAuth: function(email, token, cb) {
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
  auth: function(email, token, cb) {
    var self = this;
    var tokenBuf = new Buffer(token, 'base64');
    this.loadOrAdd(email, function(err, storedToken) {
      if (err != null) { cb(err); return; }
      // Deny blocked emails.
      if (storedToken.blocked) { cb(null, false); return; }
      try {
        // Hash the token.
        var hash = crypto.createHash(storedToken.hash);
        hash.update(tokenBuf);
        var hashedToken = hash.digest('base64');
        cb(null, hashedToken === storedToken.token);
      } catch(e) { cb(e); }
    });
  },
};
