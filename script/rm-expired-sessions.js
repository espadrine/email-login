#!/usr/bin/env node

var path = require('path');
var fs = require('fs');

// Slicing 2 items to omit `node scriptname`.
if (/\/node$/.test(process.argv[0])) {
  var argv = process.argv.slice(2);
} else {
  var argv = process.argv.slice(1);
}
// The shadow directory is ./shadow by default.
if (argv[0] !== undefined) {
  var shadow = argv[0];
} else {
  var shadow = './shadow';
}

var readFile = function(data) {
  return new Promise(function(resolve, reject) {
    fs.readFile(data.file, function(err, value) {
      if (err != null) { reject(err); return; }
      var content = '' + value;
      try {
        var json = JSON.parse(content);
      } catch(e) { reject(e); return; }
      data.json = json;
      resolve(data);
    });
  });
};

var checkExpiry = function(data) {
  var now = Date.now();
  var expirationIsInThePast = (data.json.expire < now);
  data.expired = expirationIsInThePast;
  return Promise.resolve(data);
};

var deleteSessionIfExpired = function(data) {
  if (data.expired) {
    return new Promise(function(resolve, reject) {
      fs.unlink(data.file, function(err) {
        if (err != null) { reject(err); return; }
        resolve(data);
      });
    });
  } else {
    return Promise.resolve(data);
  }
};

var findSessionFiles = function(data) {
  return new Promise(function(resolve, reject) {
    var sessionDir = path.join(data.shadow, 'session');
    fs.readdir(sessionDir, function(err, files) {
      if (err != null) { reject(err); return; }
      data.files = files.map(file => path.join(sessionDir, file));
      resolve(data);
    });
  });
};

var deleteExpiredSessions = function(data) {
  return Promise.all(data.files.map(function(file) {
    return readFile({file: file})
      .then(checkExpiry)
      .then(deleteSessionIfExpired);
  }));
};

process.on('unhandledRejection', err => { throw err })

findSessionFiles({shadow: shadow})
  .then(deleteExpiredSessions);
