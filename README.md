# Email Login

Multi-device passwordless authentication library.

```js
var EmailLogin = require('email-login');
var emailLogin = new EmailLogin({directory: './shadow'});

server.post('signup', (req, res) => {
  emailLogin.login((err, token, session) => {
    res.setCookie('token', token);
    session.id  // Unique session identifier (a base64url string)
    emailLogin.proveEmail({token: token, email: req.email}, (err) => {
      // Sent verification email.
    });
  });
});

server.post('login', (req, res) => {
  emailLogin.confirmEmail(req.cookie.token, req.token, (err, token, session) =>{
    session.email            // you@example.com
    session.emailVerified()  // true
    if (token) { res.setCookie('token', token); }
  });
});

server.request((req, res) => {
  emailLogin.authenticate(req.cookie.token, (err, authenticated, session) => {
    // Set the current identity.
    if (authenticated) {
      res.user = {id: session.id};
      if (session.emailVerified()) {  // Or you can refuse auth if you want.
        res.user.email = session.email;
      }
    } else { res.write('Authentication failed.'); }
  });
});
```

The shadow directory contains the tokens of all identities.
Each device is authenticated independently with a session.
(For instance, with a secure httpOnly cookie containing the token.)
Identities are determined by an email address.
They are linked to all sessions that have confirmed that email address.

Confirmation of an email address happens by sending an email with a link like
https://example.com/login/?email=<email>&token=<base64>.
We store the temporary hashed token in the shadow directory.
Since only the email address has that token, if we receive a correct link, we
know it was from the email address' owner.

Session IDs are random 256-bit numbers (more than UUID and IPv6 addresses).
Tokens are random 256-bit numbers. They are hashed server-side on disk.
To avoid spamming email addresses, discard login attempts for which there was
a login request within 5 minutes (so that we send at most 1 email every 5
minutes to each email address).

Technically, this is not a passwordless system, as the cross-device password
authentication is provided by the email address provider. Having an email
address ensures that we can contact the owner. This system has the following
properties:
- Getting read access to the server's hard drive doesn't give login access,
since the tokens are random and hashed.
- Sessions are identified by unique random 256-bit integers.
- Identities are identified by their email address, which is also a means to
communicate with the corresponding user.
- A random token can be stored as a secure cookie on the user's computer.
- A logout resets the token and removes the session, allowing further security
if needed.

## Pros

- Low barrier to sign-up (no password to remember, no tab switching required
  for the first log-in — or any log-in, depending on your needs).
- Can send messages to users by design (we have an email address).
- Users' security isn't compromized even if the server's hard drive is seized.
- If storing in a secure httpOnly cookie, the website can support third-party
  scripts.

## Cons

- Do not use this for webmail applications. That would risk infinite recursion
  in principle, and users being stuck in practice.
- Requires TLS for every request where the user is logged in (not really a con,
  that is pretty important for every authentication system).
- Does not solve the deficiencies of cookies or encrypted client-side storage.

# Design

World 1. The laptop clicks on “Log In”. It stores a token `A`. The
laptop is authenticated with it, but the server cannot trust the email.

    ┌──┐┌── Laptop A
    │A ├┼── Mobile
    └──┘└── Public computer

World 2, happens after World 1. The laptop confirms the email. The server
knows that the email is verified for A. Sending email is enabled.

    ┌──┐┌── Laptop A:@
    │A ├┼── Mobile
    └──┘└── Public computer

World 3, happens after World 2. The mobile clicks on “Log In”. It stores a
token `B`. The mobile can be authenticated with it, but is not associated to the
email from the laptop.

    ┌──┐┌── Laptop A:@
    │AB├┼── Mobile B
    └──┘└── Public computer

World 4, happens after World 3. The mobile confirms the email. The mobile
receives the same authentication token.

    ┌──┐┌── Laptop A:@
    │AB├┼── Mobile B:@
    └──┘└── Public computer

World 5, happens after World 4. The public computer logs in as C, comfirms the
email, logs out from the current computer. That only destroys the local cookie.

    ┌──┐┌── Laptop A:@
    │AB├┼── Mobile B:@
    └──┘└── Public computer

World 6, happens after World 4. The mobile deletes its account. The server
authenticates that logout. It destroys all sessions associated with that email.
If the laptop tries to connect, the server resets its cookie.

    ┌──┐┌── Laptop A:@
    │  ├┼── Mobile
    └──┘└── Public computer

World 7, happens after World 1. The mobile confirms the email.
The confirmation succeeds for both the laptop and mobile.

    ┌──┐┌── Laptop A:@
    │AB├┼── Mobile B:@
    └──┘└── Public computer

# TODO

- Logout
- Account deletion
- Detecting logging request spamming
- Allow user-defined storage primitives for the Registry
