function NotFoundError(message) {
  this.name = "NotFoundError";
  this.message = (message || "");
}

NotFoundError.prototype = Error.prototype;

module.exports = NotFoundError;
