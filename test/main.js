var accountTest = require('./account.js');
var registryTest = require('./registry.js');
var apiTest = require('./api.js');
process.on('unhandledRejection', err => { throw err })

accountTest(function() {
  registryTest(function() {
    apiTest(function() {
      console.log('done.');
    });
  });
});
