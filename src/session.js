// Sessions identify a device. They have an id (uuid-like number)
// and a secret. They can prove that they are linked to an email.
// To perform this proof, they need a temporary secret.

var crypto = require('crypto');

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
  this.account = null;
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
    this.proofCreatedAt = currentTime();
    this.email = email;
    return rand256;
  },
  emailVerified: function() {
    return (!!this.email) && (this.proofCreatedAt === 0);
  },
};

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

function base64url(buf) {
  if (typeof buf === 'string') { buf = new Buffer(buf); }
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/=/g, '');
}

function bufferFromBase64url(string) {
  string = string.replace(/\-/g, '+').replace(/_/g, '/');
  return Buffer(string, 'base64');
}

// Test helper functions

// Return a timestamp in milliseconds.
function currentTime() {
  return +(new Date());
}

function changeCurrentTime(f) { currentTime = Session.currentTime = f; }


Session.newSession = newSession;
Session.base64url = base64url;
Session.bufferFromBase64url = bufferFromBase64url;
Session.currentTime = currentTime;
Session.changeCurrentTime = changeCurrentTime;
module.exports = Session;
