// Database implementation using the PostgreSQL wire protocol.
// eg. CockroachDB (tested), PostgreSQL (in theory).

var Session = require('../session.js');
var Account = require('../account.js');
var NotFoundError = require('./not-found-error.js');

// options: same as the configuration of the pg package.
//   Fields include host, port, user, database, password.
//   Also:
//   - sessionTableName: name of the table containing session data.
//   - accountTableName: name of the table containing claim data.
//   - pg: the exported object from `require('pg')`.
function PgDb(options) {
  options.sessionTableName = options.sessionTableName ||
    'sessions';
  options.accountTableName = options.accountTableName ||
    'accounts';
  this.options = options;
  this.sessionTableName = options.sessionTableName;
  this.accountTableName = options.accountTableName;
  this.pg = options.pg;
}

var sessionFields = [
  "id", "hash", "token", "created_at", "expire", "last_auth", "claims"
];
var accountFields = ["id", "sessions", "data"];

PgDb.prototype = {
  // cb: function(err: Error)
  setup: function(cb) {
    var self = this;
    var sessionTableName = self.sessionTableName;
    var accountTableName = self.accountTableName;
    self.pool = new self.pg.Pool(self.options);
    // FIXME: give access to the API's consumer.
    self.pool.on('error', function(err, client) {
      console.error("pg-pool error:", err);
    });
    self.query(
      "CREATE TABLE IF NOT EXISTS " + sessionTableName + " (" +
        "id TEXT PRIMARY KEY NOT NULL, " +
        "hash TEXT NOT NULL, " +
        "token TEXT NOT NULL, " +
        "created_at TIMESTAMPTZ NOT NULL, " +
        "expire TIMESTAMPTZ NOT NULL, " +
        "last_auth TIMESTAMPTZ NOT NULL, " +
        "claims TEXT NOT NULL" +
      ")",
      function(err) {
        if (err != null) { cb(err); return; }
        self.query(
          "CREATE TABLE IF NOT EXISTS " + accountTableName + " (" +
            "id TEXT PRIMARY KEY NOT NULL, " +  // Concatenates type and id.
            "sessions TEXT NOT NULL, " +
            "data TEXT NOT NULL" +
          ")",
          cb
        );
      }
    );
  },

  // cb: function(err: Error, session: Session)
  createSession: function(session, cb) {
    var sessionTableName = this.sessionTableName;
    try {
      var claimsJson = JSON.stringify(session.claims);
    } catch(e) { cb(e); return; }
    this.query(
      "INSERT INTO " + sessionTableName + " " +
      "(" + this.sessionFieldsQuery() + ") VALUES (" +
        "$1::text, $2::text, $3::text, " +
        "$4::timestamptz, $5::timestamptz, $6::timestamptz, " +
        "$7::text" +
      ")",
      [
        String(session.id),
        String(session.hash),
        String(session.token),
        new Date(session.createdAt),
        new Date(session.expire),
        new Date(session.lastAuth),
        claimsJson,
      ],
      function(err) {
        if (err != null) { cb(err); return; }
        cb(null, session);
      }
    );
  },

  // Given a session ID, return a Session object in a callback.
  // A session that is not present in the database is an error.
  // id: String
  // cb: function(err: Error, res: Session | null)
  readSession: function(id, cb) {
    var self = this;
    var sessionTableName = self.sessionTableName;
    this.query(
      "SELECT " + this.sessionFieldsQueryWithTable() + " " +
      "FROM " + sessionTableName + " " +
      "WHERE id = $1::text LIMIT 1",
      [String(id)],
      function(err, res) {
        if (err != null) { cb(err); return; }
        if (res.rows.length === 0) {
          cb(new NotFoundError("Session " + id + " not found"));
          return;
        }
        try {
          var session = self.decodeSession(res);
        } catch(e) { cb(e); return; }
        cb(null, session);
      }
    );
  },

  // Save the session information to the database.
  // If the session does not exist, creates the session.
  // session: Session
  // cb: function(err: Error)
  updateSession: function(session, cb) {
    var sessionTableName = this.sessionTableName;
    try {
      var claimsJson = JSON.stringify(session.claims);
    } catch(e) { cb(e); return; }
    this.query(
      "UPDATE " + sessionTableName + " SET " +
        "hash = $2::text, " +
        "token = $3::text, " +
        "created_at = $4::timestamptz, " +
        "expire = $5::timestamptz, " +
        "last_auth = $6::timestamptz, " +
        "claims = $7::text " +
      "WHERE id = $1::text",
      [
        String(session.id),
        String(session.hash),
        String(session.token),
        new Date(session.createdAt),
        new Date(session.expire),
        new Date(session.lastAuth),
        String(claimsJson),
      ],
      cb
    );
  },

  // Delete the session from the database.
  // If the session does not exist, this is not an error.
  // id: String
  // cb: function(err: Error)
  deleteSession: function(id, cb) {
    var sessionTableName = this.sessionTableName;
    this.query(
      "DELETE FROM " + sessionTableName + " " +
      "WHERE id = $1::text",
      [String(id)],
      cb
    );
  },

  // cb: function(err: Error, account: Account)
  createAccount: function(account, cb) {
    var self = this;
    var accountTableName = this.accountTableName;
    try {
      var sessionsJson = JSON.stringify(account.sessionIds);
    } catch(e) { cb(e); return; }
    try {
      var dataJson = JSON.stringify(account.data);
    } catch(e) { cb(e); return; }
    this.query(
      "INSERT INTO " + accountTableName + " " +
      "(" + self.accountFieldsQuery() + ") VALUES (" +
        "$1::text, $2::text, $3::text" +
      ")",
      [
        String(account.type + ":" + account.id),
        String(sessionsJson),
        String(dataJson),
      ],
      function(err) {
        if (err != null) { cb(err); return; }
        cb(null, account);
      }
    );
  },

  // Given an account ID, return an Account object in a callback.
  // An account that is not present in the database is an error.
  // type: String
  // id: String
  // cb: function(err: Error, res: Account | null)
  readAccount: function(type, id, cb) {
    var self = this;
    var accountTableName = self.accountTableName;
    this.query(
      "SELECT " + this.accountFieldsQuery() + " " +
      "FROM " + accountTableName + " " +
      "WHERE id = $1::text LIMIT 1",
      [String(type + ":" + id)],
      function(err, res) {
        if (err != null) { cb(err); return; }
        if (res.rows.length === 0) {
          cb(new NotFoundError("Account " + type +
            " " + id + " not found"));
          return;
        }
        try {
          var account = self.decodeAccount(type, id, res);
        } catch(e) { cb(e); return; }
        cb(null, account);
      }
    );
  },

  // Save the account information to the database.
  // If the account does not exist, creates the account.
  // account: Account
  // cb: function(err: Error)
  updateAccount: function(account, cb) {
    var accountTableName = this.accountTableName;
    try {
      var sessionsJson = JSON.stringify(account.sessionIds);
    } catch(e) { cb(e); return; }
    try {
      var dataJson = JSON.stringify(account.data);
    } catch(e) { cb(e); return; }
    this.query(
      "UPDATE " + accountTableName + " SET " +
        "sessions = $2::text, " +
        "data = $3::text " +
      "WHERE id = $1::text",
      [
        String(account.type + ":" + account.id),
        String(sessionsJson),
        String(dataJson),
      ],
      cb
    );
  },

  // Delete the account from the database.
  // If the account does not exist, this is not an error.
  // type: String
  // id: String
  // cb: function(err: Error)
  deleteAccount: function(type, id, cb) {
    if (id == null) { cb(Error('Null id')); return; }
    var accountTableName = this.accountTableName;
    this.query(
      "DELETE FROM " + accountTableName + " " +
      "WHERE id = $1::text",
      [type + ":" + id],
      cb
    );
  },

  // Execute the SQL in this.pool.
  // cb: function(err: Error)
  query: function(sql, params, cb) {
    this.pool.query(sql, params, cb);
  },

  sessionFieldsQuery: function() {
    return sessionFields.join(", ");
  },

  sessionFieldsQueryWithTable: function() {
    var self = this;
    return sessionFields
      .map(function(sessionField) {
        return self.sessionTableName + "." + sessionField;
      })
      .join(", ");
  },

  sessionUpdateQuery: function() {
    var sessionFieldsLen = sessionFields.length;
    var sessionUpdateQuery = "UPDATE SET ";
    // We purposefully skip the id.
    for (var i = 1; i < sessionFieldsLen - 1; i++) {
      sessionUpdateQuery += sessionFields[i] + " = " +
        "EXCLUDED." + sessionFields[i] + ", ";
    }
    if (sessionFieldsLen > 0) {
      sessionUpdateQuery += sessionFields[i] + " = " +
        "EXCLUDED." + sessionFields[i];
    }
    return sessionUpdateQuery;
  },

  accountFieldsQuery: function() {
    return accountFields.join(", ");
  },

  // Takes a SQL response, returns a Session.
  decodeSession: function(res) {
    var row = res.rows[0];
    var claims = JSON.parse(row.claims);
    return new Session(String(row.id), String(row.hash), String(row.token),
      +row.created_at, +row.expire, +row.last_auth, claims);
  },

  // Takes a SQL response, returns an Account.
  decodeAccount: function(type, id, res) {
    var row = res.rows[0];
    var sessions = JSON.parse(row.sessions);
    var data = JSON.parse(row.data);
    return new Account(String(type), String(id), sessions, data);
  },
};

module.exports = PgDb;
