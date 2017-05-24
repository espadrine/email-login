const assert = require('assert');
const PgDb = require('../src/db/pg.js');

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
    const createTable = "CREATE TABLE IF NOT EXISTS ";
    const fieldType = /^TEXT|TIMESTAMPTZ$/;
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
    }
    cb();
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
});
