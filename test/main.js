var registryTest = require('./registry.js');
var apiTest = require('./api.js');
process.on('unhandledRejection', err => { throw err })

registryTest(function() {
  apiTest(function() {
    console.log('done.');
  });
});
