var registryTest = require('./registry.js');
var apiTest = require('./api.js');

registryTest(function() {
  apiTest(function() {
    console.log('done.');
  });
});
