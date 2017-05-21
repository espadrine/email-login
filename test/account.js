const assert = require('assert');
const Account = require('../src/account.js');

describe("Account", function() {
  it("should add a session", function() {
    let account = new Account('email', 'a@a');
    account.addSession({id: 'Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09'});
    assert.equal(1, account.sessionIds.length);
    assert.equal('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09', account.sessionIds[0]);
  });

  it("should remove a session", function() {
    let account = new Account('email', 'a@a');
    account.addSession({id: 'aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09'});
    account.addSession({id: 'Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09'});
    account.rmSession('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09');
    assert.equal(1, account.sessionIds.length);
    assert.equal('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09', account.sessionIds[0]);
    account.rmSession('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09');
    assert.equal(0, account.sessionIds.length);
    account.rmSession('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09');
    assert.equal(0, account.sessionIds.length);
  });

  it("should do nothing when removing absent sessions", function() {
    let account = new Account('email', 'a@a');
    account.addSession({id: 'aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09'});
    account.rmSession('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09');
    assert.equal(1, account.sessionIds.length);
    assert.equal('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09', account.sessionIds[0]);
  });
});
