// Accounts identify all sessions associated to the same email.

function Account(email, sessionIds) {
  this.email = email;
  this.sessionIds = sessionIds || []; // list of base64url session identifiers.
}

Account.prototype = {
  addSession: function(session) {
    this.sessionIds.push(session.id);
  },
  rmSession: function(sessionId) {
    var rmid = this.sessionIds.indexOf(sessionId);
    this.sessionIds.splice(rmid, 1);
  },
};

module.exports = Account;
