var nodemailer = require('nodemailer');

// options: passed to nodemailer.createTransport()
// - secure
// - host, eg. mail.gandi.net
// - name, eg. thaddee.tyl@example.com
// - auth
//   - user, eg. thaddee.tyl@example.com
//   - pass
// - block: true to prevent mail from being sent.
function Mailer(options) {
  this.block = options.block;
  if (!this.block) {
    this.transporter = nodemailer.createTransport(options);
    this.from = options.from;
  }
}

Mailer.prototype = {
  // options
  // - to: thaddee.tyl@example.com
  // - subject: hello
  // - text: how are you
  // - html: how <em>are</em> you
  // cb: function(err, info)
  send: function(options, cb) {
    if (this.block) { return cb(); }
    var mailOptions = {
      from: this.from,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
    };

    transporter.sendMail(mailOptions, function(err, info) {
      if (err != null) { return cb(err); }
      cb(null, info);
    });
  },
};

module.exports = Mailer;
