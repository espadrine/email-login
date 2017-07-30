// Sessions identify a device. They have an id (uuid-like number)
// and a secret. They can prove that they are linked to an email.
// To perform this proof, they need a temporary secret.

var crypto = require('crypto');

var SESSION_LIFESPAN = 9 * 30 * 24 * 3600000; // ms = 9 months.
var SESSION_RENEWAL = 24 * 3600000; // ms = 1 day.

function Session(id, hash, token, createdAt, expire, renew, lastAuth, claims) {
  id = (id !== undefined)? ('' + id): '';
  hash = (hash !== undefined)? ('' + hash): '';
  token = (token !== undefined)? ('' + token): '';
  lastAuth = (lastAuth !== undefined)? (+lastAuth): 0;
  createdAt = (createdAt !== undefined)? (+createdAt): currentTime();
  expire = (expire !== undefined)? (+expire):
    (currentTime() + SESSION_LIFESPAN);
  renew = (renew !== undefined)? (+renew):
    (currentTime() + SESSION_RENEWAL);
  claims = (claims instanceof Array)? claims: [];
  this.id = id;
  this.hash = hash;
  this.token = token;
  this.createdAt = createdAt;
  this.lastAuth = lastAuth;
  this.expire = expire;
  this.renew = renew;
  this.claims = claims;
  // Cached link to a loaded instance of the email's account.
  this.account = undefined;
}

Session.prototype = {
  // Set the token, return it as a buffer.
  // Warning: can throw.
  setToken: function() {
    var alg = 'sha256';
    var hash = crypto.createHash(alg);
    var rand256 = crypto.randomBytes(16);
    hash.update(rand256);
    this.hash = alg;
    this.token = hash.digest('base64');
    return rand256;
  },
  // Return a claim with the given type and id.
  // Undefined if it cannot be found.
  findClaim: function(type, id) {
    var claims = this.claims;
    var len = claims.length;
    for (var i = 0; i < len; i++) {
      // Start with checking the id, as it is more likely to discriminate things
      // faster.
      if (claims[i].id === id && claims[i].type === type) {
        return claims[i];
      }
    }
  },
  // Return a claim with the given type.
  // Undefined if it cannot be found.
  findClaimType: function(type, id) {
    var claims = this.claims;
    var len = claims.length;
    for (var i = 0; i < len; i++) {
      if (claims[i].type === type) {
        return claims[i];
      }
    }
  },
  // Add a claim. Returns the added claim.
  addClaim: function(type, id) {
    var claims = this.claims;
    var claim = this.findClaim(type, id);
    if (claim === undefined) {
      claim = { type: type, id: id, proved: 0 };
      claims.push(claim);
    }
    return claim;
  },
  // Set the claim as proved.
  claimProved: function(type, id) {
    var claim = this.findClaim(type, id);
    if (claim !== undefined) {
      this.proveClaim(claim);
    }
  },
  // Set the claim as proved directly.
  // If you have the claim, this is faster than claimProved().
  proveClaim: function(claim) {
    claim.proved = currentTime();
  },
  emailVerified: function() {
    var claim = this.findClaimType('email');
    if (claim !== undefined) {
      return claim.proved > 0;
    } else {
      return false;
    }
  },
  // The first email we find in a claim, or undefined.
  get email() {
    var claim = this.findClaimType('email');
    if (claim !== undefined) {
      return claim.id;
    }
  },
  set email(newId) {
    var claim = this.findClaimType('email');
    if (claim !== undefined) {
      claim.id = newId;
      return claim.id;
    }
  },
};

function newSession() {
  // An id is always a 256-bit base64url random string.
  // Think of it as a stronger UUID.
  var rand256 = crypto.randomBytes(16);
  var id = base64url(rand256.toString('base64'));
  return new Session(
    id,
    '',    // hash
    '',    // token
    undefined,  // set the creation date to now
    undefined,  // default expire
    undefined,  // default renew
    undefined,  // last auth
    []     // claims
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
var currentTime = function() {
  return +(new Date());
};

function changeCurrentTime(f) { currentTime = Session.currentTime = f; }


Session.newSession = newSession;
Session.base64url = base64url;
Session.bufferFromBase64url = bufferFromBase64url;
Session.currentTime = currentTime;
Session.changeCurrentTime = changeCurrentTime;
Session.SESSION_RENEWAL = SESSION_RENEWAL;
module.exports = Session;
