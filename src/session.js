// Sessions identify a device. They have an id (uuid-like number)
// and a secret. They can prove that they are linked to an email.
// To perform this proof, they need a temporary secret.

var crypto = require('crypto');

var SESSION_LIFESPAN = 9 * 30 * 24 * 3600000; // ms = 9 months.

function Session(id, hash, token, createdAt, expire, lastAuth,
    email, emailProved, emailProof) {
  id = (id !== undefined)? ('' + id): '';
  hash = (hash !== undefined)? ('' + hash): '';
  token = (token !== undefined)? ('' + token): '';
  lastAuth = (lastAuth !== undefined)? (+lastAuth): 0;
  createdAt = (createdAt !== undefined)? (+createdAt): currentTime();
  expire = (expire !== undefined)? (+expire):
    (currentTime() + SESSION_LIFESPAN);
  email = (email !== undefined)? ('' + email): '';
  emailProved = (emailProved !== undefined)? (!!emailProved): false;
  emailProof = (emailProof !== undefined)? ('' + emailProof): '';
  this.id = id;
  this.hash = hash;
  this.token = token;
  this.createdAt = createdAt;
  this.lastAuth = lastAuth;
  this.expire = expire;
  // Primary email as a string; an empty string indicates lack of information.
  this.email = email;
  this.emailProved = emailProved;
  // Id of a Session which holds proof information, empty string if unknown.
  this.emailProof = emailProof;
  // Cached link to a loaded instance of the email's account.
  this.account = undefined;
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
  emailVerified: function() {
    return this.emailProved;
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
    undefined,  // set the creation date to now
    undefined,  // default expire
    undefined,  // last auth
    '',    // email
    false, // emailProved
    ''     // emailProof
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
