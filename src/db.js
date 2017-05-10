// Database description, interface, and default implementation
// (backed by a file system).

var fs = require('fs');
var fsos = require('fsos');
var path = require('path');
var Session = require('./session.js');
var Account = require('./account.js');
var NotFoundError = require('./db-not-found-error.js');

// The options are an object of any form, depending on the database's needs.
// The default implementation requires {dir: '/path/to/db/directory'}.
function DirectoryDb(options) {
  this.options = options;
}

DirectoryDb.prototype = {
  // cb: function(err: Error)
  setup: function(cb) {
    var self = this;
    self.mkdirname(self.options.dir, function(err) {
      if (err != null) { return cb(err); }
      self.mkdirname(path.join(self.options.dir, 'session'), function(err) {
        if (err != null) { return cb(err); }
        self.mkdirname(path.join(self.options.dir, 'email'), cb);
      });
    });
  },

  // cb: function(err: Error, session: Session)
  createSession: function(cb) {
    this.updateSession(Session.newSession(), cb);
  },

  // Given a session ID, return a Session object in a callback.
  // A session that is not present in the database is an error.
  // id: String
  // cb: function(err: Error, res: Session | null)
  readSession: function(id, cb) {
    var self = this;
    var file = path.join(self.options.dir, 'session', id);
    fsos.get(file).then(function(json) {
      json = "" + json;
      try {
        var session = self.decodeSession(json);
      } catch(e) { return cb(e); }
      cb(null, session);
    }).catch(function(err) {
      if (err.code === 'ENOENT') {
        cb(new NotFoundError("Session " + id + " not found"));
      } else {
        cb(err);
      }
    });
  },

  // Save the session information to the database.
  // If the session does not exist, creates the session.
  // session: Session
  // cb: function(err: Error)
  updateSession: function(session, cb) {
    var file = path.join(this.options.dir, 'session', session.id);
    try {
      var encodedFile = this.encodeSession(session);
    } catch(e) { return cb(e); }
    fsos.set(file, encodedFile).then(cb).catch(cb);
  },

  // Delete the session from the database.
  // If the session does not exist, this is not an error.
  // id: String
  // cb: function(err: Error)
  deleteSession: function(id, cb) {
    var file = path.join(this.options.dir, 'session', id);
    fsos.delete(file).then(cb).catch(cb);
  },

  // cb: function(err: Error, account: Account)
  createAccount: function(type, id, cb) {
    this.updateAccount(new Account(type, id), cb);
  },

  // Given an account ID, return an Account object in a callback.
  // An account that is not present in the database is an error.
  // type: String
  // id: String
  // cb: function(err: Error, res: Account | null)
  readAccount: function(type, id, cb) {
    var self = this;
    if (id == null) { return cb(Error('Null id')); }
    var idb64 = Session.base64url(id);
    var file = path.join(self.options.dir, type, idb64);
    fsos.get(file).then(function(json) {
      json = "" + json;
      try {
        var account = self.decodeAccount(json);
      } catch(e) { return cb(e); }
      cb(null, account);
    }).catch(function(err) {
      if (err.code === 'ENOENT') {
        cb(new NotFoundError("Account " + type + " " + id + " not found"));
      } else {
        cb(err);
      }
    });
  },

  // Save the account information to the database.
  // If the account does not exist, creates the account.
  // account: Account
  // cb: function(err: Error)
  updateAccount: function(account, cb) {
    if (account == null) { return cb(Error('Null account')); }
    if (account.id == null) { return cb(Error('Null account id')); }
    var idb64 = Session.base64url(account.id);
    var file = path.join(this.options.dir, account.type, idb64);
    try {
      var encodedFile = this.encodeAccount(account);
    } catch(e) { return cb(e); }
    fsos.set(file, encodedFile).then(cb).catch(cb);
  },

  // Delete the account from the database.
  // If the account does not exist, this is not an error.
  // type: String
  // id: String
  // cb: function(err: Error)
  deleteAccount: function(type, id, cb) {
    if (id == null) { return cb(Error('Null id')); }
    var idb64 = Session.base64url(id);
    var file = path.join(this.options.dir, type, idb64);
    fsos.delete(file).then(cb).catch(cb);
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

  // Takes a Session, returns a JSON string.
  encodeSession: function(session) {
    return JSON.stringify({
      id: session.id,
      hash: session.hash,
      token: session.token,
      createdAt: session.createdAt,
      expire: session.expire,
      lastAuth: session.lastAuth,
      claims: session.claims,
    });
  },

  // Takes a JSON string, returns a Session.
  decodeSession: function(json) {
    var json = JSON.parse(json);
    return new Session(json.id, json.hash, json.token, json.createdAt,
      json.expire, json.lastAuth, json.claims);
  },

  // Takes an account, returns a JSON string.
  encodeAccount: function(account) {
    return JSON.stringify({
      type: account.type,
      id: account.id,
      sessions: account.sessionIds
    });
  },

  // Takes a JSON string, returns an Account.
  decodeAccount: function(json) {
    var json = JSON.parse(json);
    return new Account(json.type, json.id, json.sessions);
  },
};


module.exports = DirectoryDb;
