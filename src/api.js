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
  // options:
  // - email
  // - subject: function(name)
  // - name (optional): used in the default subject.
  // - textMessage: function(linkToken, rootUrl)
  // - htmlMessage: function(linkToken, rootUrl)
  // - rootUrl (optional): used in the message.
  // cb: function(err, linkToken)
  login: function(options, cb) {
    var email = options.email;
    var subject = options.subject || defaultSubject;
    var textMessage = options.textMessage || defaultTextMessage;
    var htmlMessage = options.htmlMessage || defaultHtmlMessage;
    var self = this;

    self.registry.login(email, function(err, secret) {
      if (err != null) { return cb(err); }
      var linkToken = encodeLinkToken(email, secret);
      self.mailer.send({
        to: email,
        subject: subject(options.name),
        text: textMessage(linkToken, options.rootUrl),
        html: htmlMessage(linkToken, options.rootUrl),
      }, function(err) { cb(err, linkToken); });
    });
  },

  // cb: function(err, cookieToken)
  // If the token is undefined, the email did not match the token
  // in the linkToken.
  confirm: function(linkToken, cb) {
    var self = this;
    var elements = decodeLinkToken(linkToken);
    var email = elements.email;
    var token = elements.token;

    self.registry.confirm(email, token, function(err, confirmed) {
      if (err != null) { return cb(err); }
      if (!confirmed) { return cb(null); }
      // TODO: only reset if the secret doesn't already exist.
      self.registry.reset(email, function(err, secret) {
        if (err != null) { return cb(err); }
        var cookieToken = encodeLinkToken(email, secret);
        cb(err, cookieToken);
      });
    });
  },

  // cb: function(err, email)
  // If the email is undefined, the authentication failed.
  authenticate: function(cookieToken, cb) {
    var elements = decodeLinkToken(cookieToken);
    var email = elements.email;
    var token = elements.token;

    this.registry.auth(email, token, function(err, authenticated) {
      if (err != null) { return cb(err); }
      if (!authenticated) { return cb(null); }
      cb(null, email);
    });
  },
};

// Primitives

// Return {email: string, token: base64}
function decodeLinkToken(base64) {
  var elements = base64.split('.');
  var emailBase64 = elements[0];
  var tokenBase64 = elements[1];
  return {
    email: bufferFromBase64url(emailBase64).toString(),
    token: tokenBase64.replace(/\-/g, '+').replace(/_/g, '/'),
  };
}

// email: string, secret: Buffer.
// The link token is <base64url of the email>.<base64url of the secret>.
function encodeLinkToken(email, secret) {
  return base64url(email) + '.' + base64url(secret);
}

function defaultSubject(name) {
  return '[' + name + '] Identity verification'
}

function defaultTextMessage(linkToken, rootUrl) {
  rootUrl = rootUrl || 'https://127.0.0.1/';
  return 'Hi!\n\n' +
    'You can confirm that you own this email address by clicking on this link:\n\n' +
    rootUrl + 'login?token=' + linkToken + '\n\n' +
    'Please point your browser to that URL and you will be good to go!\n\n' +
    'Cheers!';
}

function defaultHtmlMessage(linkToken, rootUrl) {
  rootUrl = rootUrl || 'https://127.0.0.1/';
  return '<p>Hi!</p>\n\n' +
    '<p>You can confirm that you own this email address by clicking' +
    '<a href="' + escapeHtml(rootUrl) + 'login?token=' + escapeHtml(linkToken) + '">' +
    'here</a>.</p>' +
    '<p>Cheers!</p>';
}

function escapeHtml(text) {
  return text.replace(/\&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = Api;
