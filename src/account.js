// Accounts identify all sessions associated to the same identifier
// (eg, an email address).

function Account(type, id, sessionIds, data) {
  this.type = type;
  this.id = id;
  this.sessionIds = sessionIds || []; // list of base64url session identifiers.
  this.data = data || Object.create(null);
}

Account.prototype = {
  addSession: function(session) {
    this.sessionIds.push(session.id);
  },
  rmSession: function(sessionId) {
    var rmid = this.sessionIds.indexOf(sessionId);
    if (rmid >= 0) {
      this.sessionIds.splice(rmid, 1);
    }
  },
};

module.exports = Account;
