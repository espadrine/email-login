var assert = require('assert');
if (this.Promise === undefined) {
  this.Promise = require('promise');
  require('promise/lib/rejection-tracking').enable();
}
var Account = require('../src/account.js');

var addSession = function() {
  return new Promise(function(resolve, reject) {
    var account = new Account('email', 'a@a');
    account.addSession({id: 'Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09'});
    assert.equal(1, account.sessionIds.length);
    assert.equal('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09', account.sessionIds[0]);
    resolve();
  });
};

var removeSession = function() {
  return new Promise(function(resolve, reject) {
    var account = new Account('email', 'a@a');
    account.addSession({id: 'aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09'});
    account.addSession({id: 'Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09'});
    account.rmSession('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09');
    assert.equal(1, account.sessionIds.length);
    assert.equal('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09', account.sessionIds[0]);
    account.rmSession('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09');
    assert.equal(0, account.sessionIds.length);
    account.rmSession('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09');
    assert.equal(0, account.sessionIds.length);
    resolve();
  });
};

var removeAbsentSession = function() {
  return new Promise(function(resolve, reject) {
    var account = new Account('email', 'a@a');
    account.addSession({id: 'aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09'});
    account.rmSession('Z1JWQTVJSEN6RjIyWjY5cDN0Mnl0dz09');
    assert.equal(1, account.sessionIds.length);
    assert.equal('aWh2ak9hQU9KamE4N0VpSlRsMVVwdz09', account.sessionIds[0]);
    resolve();
  });
};

var test = function() {
  return addSession()
    .then(removeSession)
    .then(removeAbsentSession);
};

var runTest = function(cb) {
  test()
  .then(cb)
  .catch(function(err) { throw err; });
};

module.exports = runTest;
