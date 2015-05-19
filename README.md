# Email Login

```js
var emailLogin = require('email-login');

server.post('sign-up', (req, res) => {
  emailLogin.login(req.params.email, (err) => {
    // Sent verification email.
  });
});

server.post('login', (req, res) => {
  emailLogin.loginAuth(req.params.email, req.params.token, (err, token) => {
    // Set authentication cookies.
    res.cookie.email = req.params.email;
    res.cookie.token = token;
  });
});

server.request((req, res) => {
  var [email, token] = [req.cookie.email, req.cookie.token];
  emailLogin.auth(token, (err, authorized) => {
    // Set the current user.
    if (authorized) { res.user = {email: email}; }
  });
});
```

The token file contains hashed session tokens of all identities.

email, blacklisted?, last login request IP,
last login request timestamp, login token hash type, login hashed token,
creation timestamp, hash type, hashed token

We send a mail with a link like
https://example.com/login/?email=<email>&token=<base64>
and we store the temporary hashed token in the token file.
Since only the email address has that token, if we receive a correct link, we
know it was from the email address' owner. We generate a random token
(in case we were compromised while sending the email; if the last login
request was past 5 minutes ago, fail). We store the new hashed token, and
redirect the user with a secure httpOnly cookie containing the token.

Tokens are random 128-bit numbers (just like UUID and IPv6 addresses).
The stored hash is that of the original number, not its base64.
To avoid spamming email addresses, discard login attempts for which there was
a login request within 5 minutes (so that we send at most 1 email every 5
minutes to each email address).

Technically, this is not a passwordless system, as the password
authentication is provided by the email address provider. Having an email
address ensures that we can contact the owner. This system has the following
properties:
- Getting read access to the server's hard drive doesn't give login access,
since the tokens are random and hashed.
- Users are identified by their email address.
- A random temporary token is stored as a secure cookie on the user's
computer.
- A logout resets the token, allowing further security if needed.

# TODO

- Main API
- Sending emails
- Detecting loging request spamming
- Allow user-defined storage primitives for the Token Registry
