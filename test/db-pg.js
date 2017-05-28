const assert = require('assert');
const PgDb = require('../src/db/pg.js');
const NotFoundError = require('./../src/db/not-found-error.js');

const fakePg = {};
fakePg.Pool = function(options) {
  // Map from table name to list of {column: value} objects.
  this.tables = new Map();
  // Map from table name to list of {name, type, null, indices}
  this.tableSchema = new Map();
  this.options = options;
};
fakePg.Pool.prototype = {
  on(event) {},
  query(command, params, cb) {
    if (!cb) { cb = params; }
    const fieldType = /^TEXT|TIMESTAMPTZ$/;
    const createTable = "CREATE TABLE IF NOT EXISTS ";
    const insertInto = /^INSERT INTO (\w+) \(([\w, ]+)\) VALUES \(([\w\$:, ]+)\)(?: ON CONFLICT \(([\w, ]+)\))?/;
    const selectFromWhereId =
      /^SELECT ([\w,\. ]+) FROM (\w+) WHERE id = (.*) LIMIT 1$/;
    const deleteFrom =
      /^DELETE FROM (\w+) WHERE ((?: AND )?\w+ = [\w\$:, ]+)+$/;

    if (command.startsWith(createTable)) {
      const match = /^(\w+) \((.*)\)$/.exec(
        command.slice(createTable.length));
      const tableName = match[1];
      const fieldCommands = match[2].match(/(\w[\w ]*(\(.*\))?)/g);
      const fields = fieldCommands.map(field => {
        const parts = field.split(" ");
        if (!fieldType.test(parts[1])) { return; }
        const params = [...parts.slice(2)].join(' ');
        const indices = new Set();
        if (/\bPRIMARY KEY\b/.test(params)) {
          indices.add("primary");
        }
        return {
          name: parts[0],
          type: parts[1],
          null: !/\bNOT NULL\b/.test(params),
          indices: indices,
        };
      }).filter(field => field !== undefined);

      this.tables.set(tableName, []);
      const schema = [];
      this.tableSchema.set(tableName, schema);

      // Create tables and table schemas.
      fields.forEach(field => schema.push(field));

      // Augment table schemas with non-field lines.
      fieldCommands.forEach(field => {
        const primaryKey = /^PRIMARY KEY \((.*)\)$/;
        if (primaryKey.test(field)) {
          const keys = primaryKey.exec(field)[1].split(", ");
          keys.forEach(key => {
            schema.find(field => {
              if (field.name === key) {
                field.indices.add("primary");
              }
            });
          });
        }
      });

    } else if (insertInto.test(command)) {
      const match = insertInto.exec(command);
      const tableName = match[1];
      const fieldNames = match[2].split(", ");
      const fieldValues = match[3].split(", ");
      const conflictFieldNames = match[4] ? match[4].split(", ") : [];
      const table = this.tables.get(tableName);
      const newRow = {};
      fieldNames.forEach((name, i) => {
        newRow[name] = this.extractParam(fieldValues[i], params);
      });

      const matchedIdx = table.map((row, idx) => {
        if (conflictFieldNames.every(fieldName =>
          row[fieldName] === newRow[fieldName]
        )) {
          return idx;
        }
      }).filter(row => row !== undefined);

      if (matchedIdx.length > 0) {
        table[matchedIdx[0]] = newRow;
      } else {
        table.push(newRow);
      }

    } else if (selectFromWhereId.test(command)) {
      const match = selectFromWhereId.exec(command);
      const fields = match[1].split(", ").map(column => {
        return column.split(".")[1];
      });
      const tableName = match[2];
      const selectionId = this.extractParam(match[3], params);
      const table = this.tables.get(tableName);
      const rows = table.filter(row => row.id === selectionId);
      cb(null, {rows});
      return;

    } else if (deleteFrom.test(command)) {
      const match = deleteFrom.exec(command);
      const tableName = match[1];
      const filter = match[2].split(" AND ").reduce((acc, fieldFilter) => {
        const match = fieldFilter.split(" = ");
        const columnName = match[0];
        const value = this.extractParam(match[1], params);
        return acc.set(columnName, value);
      }, new Map());
      const table = this.tables.get(tableName);
      this.tables.set(tableName, table.filter(row =>
        [...filter.keys()].some(columnName =>
          row[columnName] !== filter.get(columnName))));
    }

    cb();
  },
  // param: string of a placeholder, eg. $1::text
  // params: list of values, see query()'s params.
  extractParam(param, params) {
    const match = /^\$(\d+)(?:::\w+)?$/.exec(param);
    const paramIdx = +match[1] - 1;
    return params[paramIdx];
  },
};

describe("PostgreSQL-compatible Database", function() {
  let db;
  it("should initialize database objects", function() {
    db = new PgDb({
      host: 'localhost',
      port: 1337,
      user: 'pguser',
      database: 'main_db',
      password: 'hunter2',
      sessionTableName: 'login_sessions',
      accountTableName: 'login_accounts',
      pg: fakePg,
    });
    assert.equal('localhost', db.options.host);
    assert.equal(1337, db.options.port);
    assert.equal('pguser', db.options.user);
    assert.equal('main_db', db.options.database);
    assert.equal('hunter2', db.options.password);
    assert.equal('login_sessions', db.sessionTableName);
    assert.equal('login_accounts', db.accountTableName);
    assert.equal(fakePg, db.pg);
  });

  it("should initialize database objects with defaults", function() {
    db = new PgDb({
      host: 'localhost',
      port: 1337,
      user: 'pguser',
      database: 'main_db',
      password: 'hunter2',
      pg: fakePg,
    });
    assert.equal('sessions', db.sessionTableName);
    assert.equal('accounts', db.accountTableName);
  });

  it("should create the database", function(resolve) {
    db.setup(function(err) {
      const tables = [...db.pool.tables.keys()];
      const sessionSchema = db.pool.tableSchema.get('sessions');
      const accountSchema = db.pool.tableSchema.get('accounts');

      assert.deepEqual(['sessions', 'accounts'], tables);

      assert.equal('id', sessionSchema[0].name);
      assert.equal('TEXT', sessionSchema[0].type);
      assert.equal(false, sessionSchema[0].null);
      assert(sessionSchema[0].indices.has('primary'));

      assert.equal('hash', sessionSchema[1].name);
      assert.equal('TEXT', sessionSchema[1].type);
      assert.equal(false, sessionSchema[1].null);
      assert(!sessionSchema[1].indices.has('primary'));

      assert.equal('token', sessionSchema[2].name);
      assert.equal('TEXT', sessionSchema[2].type);
      assert.equal(false, sessionSchema[2].null);
      assert(!sessionSchema[2].indices.has('primary'));

      assert.equal('created_at', sessionSchema[3].name);
      assert.equal('TIMESTAMPTZ', sessionSchema[3].type);
      assert.equal(false, sessionSchema[3].null);
      assert(!sessionSchema[3].indices.has('primary'));

      assert.equal('expire', sessionSchema[4].name);
      assert.equal('TIMESTAMPTZ', sessionSchema[4].type);
      assert.equal(false, sessionSchema[4].null);
      assert(!sessionSchema[4].indices.has('primary'));

      assert.equal('last_auth', sessionSchema[5].name);
      assert.equal('TIMESTAMPTZ', sessionSchema[5].type);
      assert.equal(false, sessionSchema[5].null);
      assert(!sessionSchema[5].indices.has('primary'));

      assert.equal('claims', sessionSchema[6].name);
      assert.equal('TEXT', sessionSchema[6].type);
      assert.equal(false, sessionSchema[6].null);
      assert(!sessionSchema[6].indices.has('primary'));

      assert.equal('type', accountSchema[0].name);
      assert.equal('TEXT', accountSchema[0].type);
      assert.equal(false, accountSchema[0].null);
      assert(accountSchema[0].indices.has('primary'));

      assert.equal('id', accountSchema[1].name);
      assert.equal('TEXT', accountSchema[1].type);
      assert.equal(false, accountSchema[1].null);
      assert(accountSchema[1].indices.has('primary'));

      assert.equal('sessions', accountSchema[2].name);
      assert.equal('TEXT', accountSchema[2].type);
      assert.equal(false, accountSchema[2].null);
      assert(!accountSchema[2].indices.has('primary'));

      resolve(err);
    });
  });

  let createdSession;
  it("should create a session", function(resolve) {
    const before = new Date();
    db.createSession(function(err, session) {
      assert(!err);
      createdSession = session;
      assert.equal('string', typeof session.id);
      assert.equal('', session.hash);
      assert.equal('', session.token);
      assert(before <= session.createdAt);
      const now = new Date();
      assert(session.createdAt <= now);
      assert(session.createdAt <= session.expire);
      assert(session.lastAuth < session.createdAt);
      assert.deepEqual([], session.claims);

      const sessionRow = db.pool.tables.get('sessions')[0];
      assert.equal(session.id, sessionRow.id);
      assert.equal(session.hash, sessionRow.hash);
      assert.equal(session.token, sessionRow.token);
      assert.equal(session.createdAt, +sessionRow.created_at);
      assert.equal(session.expire, +sessionRow.expire);
      assert.equal(session.lastAuth, +sessionRow.last_auth);
      assert.equal(JSON.stringify(session.claims), sessionRow.claims);

      resolve(err);
    });
  });

  it("should read a session", function(resolve) {
    db.readSession(createdSession.id, function(err, session) {
      assert(!err);
      assert.equal(createdSession.id, session.id);
      assert.equal(createdSession.hash, session.hash);
      assert.equal(createdSession.token, session.token);
      assert.equal(+createdSession.createdAt, +session.createdAt);
      assert.equal(+createdSession.expire, +session.expire);
      assert.equal(+createdSession.lastAuth, +session.lastAuth);
      assert.deepEqual(createdSession.claims, session.claims);

      resolve(err);
    });
  });

  it("should update a session", function(resolve) {
    createdSession.hash = 'sha256';
    createdSession.token = 'eWsyRktrVUxZVHhFZFRDWWRFb2U3Zz09';
    createdSession.claims = [{
      type: "email",
      id: "hi@example.org",
      proved: 0,
    }];

    db.updateSession(createdSession, function(err) {
      assert(!err);
      db.readSession(createdSession.id, function(err, session) {
        assert(!err);
        assert.equal(createdSession.id, session.id);
        assert.equal(createdSession.hash, session.hash);
        assert.equal(createdSession.token, session.token);
        assert.equal(+createdSession.createdAt, +session.createdAt);
        assert.equal(+createdSession.expire, +session.expire);
        assert.equal(+createdSession.lastAuth, +session.lastAuth);
        assert.deepEqual(createdSession.claims, session.claims);

        resolve(err);
      });
    });
  });

  it("should delete a session", function(resolve) {
    db.deleteSession(createdSession.id, function(err) {
      assert(!err);
      db.readSession(createdSession.id, function(err, session) {
        assert(err instanceof NotFoundError);

        resolve();
      });
    });
  });

  let createdAccount;
  it("should create an account", function(resolve) {
    db.createAccount("email", "hi@example.com", function(err, account) {
      assert(!err);
      createdAccount = account;
      assert.equal('email', account.type);
      assert.equal('hi@example.com', account.id);
      assert.deepEqual([], account.sessionIds);

      const accountRow = db.pool.tables.get('accounts')[0];
      assert.equal(account.type, accountRow.type);
      assert.equal(account.id, accountRow.id);
      assert.deepEqual(JSON.stringify(account.sessionIds),
        accountRow.sessions);

      resolve(err);
    });
  });
});
