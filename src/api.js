"use strict";

var registry = require('./registry.js');
var Mailer = require('./mailer.js');

var Registry = registry.Registry;
var base64url = registry.base64url;
var bufferFromBase64url = registry.bufferFromBase64url;

// options:
// - directory: path to storage point as a string.
// - mailer: object, see mailer.js
// cb: function(err)
function Api(options, cb) {
  this.registry = new Registry(options.directory);
  this.mailer = new Mailer(options.mailer);
  this.registry.mkdir(cb);
}

Api.prototype = {
  // cb(error, token, session)
  login: function(cb) {
    this.registry.login(function(err, secret, session) {
      if (err != null) { return cb(err); }
      var token = encodeToken(session.id, secret);
      cb(null, token, session);
    });
  },

  // options:
  // - token (a string)
  // - email
  // - subject: function(name)
  // - name (optional): used in the default subject.
  // - textMessage: function(emailToken, rootUrl)
  // - htmlMessage: function(emailToken, rootUrl)
  // - rootUrl (optional): used in the message.
  // cb: function(err, emailToken)
  proveEmail: function(options, cb) {
    var token = options.token;
    var email = options.email;
    var subject = options.subject || defaultSubject;
    var textMessage = options.textMessage || defaultTextMessage;
    var htmlMessage = options.htmlMessage || defaultHtmlMessage;
    var self = this;

    var elements = decodeToken(token);
    var id = elements.id;

    self.registry.proof(id, email, function(err, secret) {
      if (err != null) { return cb(err); }
      var emailToken = encodeToken(id, secret);
      self.mailer.send({
        to: email,
        subject: subject(options.name),
        text: textMessage(emailToken, options.rootUrl),
        html: htmlMessage(emailToken, options.rootUrl),
      }, function(err) { cb(err, emailToken); });
    });
  },

  // cb: function(err, token, session)
  // The returned token is null if the confirmation failed.
  confirmEmail: function(token, emailToken, cb) {
    var elements = decodeToken(emailToken);
    var emailId = elements.id;
    var emailSecret = elements.token;

    var self = this;
    self.registry.confirm(emailId, emailSecret,
    function(err, confirmed, session) {
      if (err != null) { return cb(err); }
      if (!confirmed) { return cb(null, null, session); }

      if (token === undefined) {
        // We received a confirmation from an unknown device.
        self.login(function(err, newToken, newSession) {
          if (err != null) { return cb(err); }
          self.registry.manualConfirmEmail(newSession.id, session.email,
          function(err) {
            if (err != null) { return cb(err); }
            cb(null, newToken, newSession);
          });
        });

      } else {
        var elements = decodeToken(token);
        var id = elements.id;
        if (session.id !== id) {
          // We received a confirmation from the wrong device.
          self.registry.manualConfirmEmail(id, session.email, function(err) {
            if (err != null) { return cb(err); }
            cb(null, token, session);
          });

        } else {
          cb(null, token, session);
        }
      }
    });
  },

  // cb: function(err, authenticated, session)
  // If the email is undefined, the authentication failed.
  authenticate: function(cookieToken, cb) {
    var elements = decodeToken(cookieToken);
    var id = elements.id;
    var token = elements.token;

    this.registry.auth(id, token, cb);
  },
};

// Primitives

// Return {id: base64url, token: base64, version: int}
function decodeToken(base64) {
  var elements = base64.split('.');
  var version = +elements[0];
  var id = elements[1];
  var tokenBase64url = elements[2];
  return {
    id: id,
    token: tokenBase64url.replace(/\-/g, '+').replace(/_/g, '/'),
    version: version,
  };
}

// id: base64url, secret: Buffer, version: int.
// The link token is
// <version>.<id as base64url>.<base64url of the secret>
function encodeToken(id, secret, version) {
  version = version || 1;
  return version + '.' + id + '.' + base64url(secret);
}

function defaultSubject(name) {
  return '[' + name + '] Identity verification'
}

function defaultTextMessage(emailToken, rootUrl) {
  rootUrl = rootUrl || 'https://127.0.0.1/';
  return 'Hi!\n\n' +
    'You can confirm that you own this email address by clicking ' +
    'on this link:\n\n' +
    rootUrl + 'login?token=' + emailToken + '\n\n' +
    'Please point your browser to that URL and you will be good to go!\n\n' +
    'Cheers!';
}

function defaultHtmlMessage(emailToken, rootUrl) {
  rootUrl = rootUrl || 'https://127.0.0.1/';
  return '<p>Hi!</p>\n\n' +
    '<p>You can confirm that you own this email address by clicking' +
    '<a href="' + escapeHtml(rootUrl) +
      'login?token=' + escapeHtml(emailToken) + '">' +
    'here</a>.</p>' +
    '<p>Cheers!</p>';
}

function escapeHtml(text) {
  return text.replace(/\&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = Api;
module.exports.encodeToken = encodeToken;
module.exports.decodeToken = decodeToken;
