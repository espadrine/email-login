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

See a more extensive example here: <https://github.com/espadrine/email-login-example>.

# Interface

`new EmailLogin(options)` returns a login system.

- `options` is an object containing:
  - `directory` is the path to the shadow directory, that will contain all the
    token information. It will be created automatically.
  - `mailer` is an object that sets up the email system to send emails to users.
    For extensive information on the options available here, see
    [nodemailer's documentation][]. To avoid having to fill it in (which can be
    annoying for certain email providers), there are plugins listed as
    [transports][], which return the correct object.
    - `block`: blocks sending mail. Set to true for testing purposes. This is
      not for nodemailer.
    - `from`: email address from which to send emails. This is not for
      nodemailer.
    - `host`: the email domain or IP address, such as `mail.google.com`.
    - `auth`: an object to get authenticated to the host.
      - `user`, eg, "admin@example.com"
      - `pass`, the password (or passphrase)

[nodemailer's documentation]: https://github.com/andris9/nodemailer-smtp-transport#usage
[transports]: http://www.nodemailer.com/#available-transports

The **login system** has the following methods.

`login(function(error, token, session))` registers a new user's session. Each
session can be associated to a device, a browser, etc. simply by storing the token
(a string) in that device / browser. See Session below for more detail.

`proveEmail(options, function(error, emailToken))` sends an email to verify that
a particular session does belong to the owner of that email address. Here are
what the options allow.

- `token`: put the token you obtained from the `login` function above.
- `email`: the email address that the session owner claims to own.
- `subject`: a function that returns a String used as the verification email's
  subject.
- `textMessage`: `function(emailToken)`, where you can insert `emailToken` in a
  URL you own. When the email owner clicks on that URL, you will extract the
  `emailToken` from the URL and call `confirmEmail` with it.
- `htmlMessage`: works just like `textMessage`, but it supports HTML and will
  display however email clients display HTML.

We provide defaults for `subject`, `textMessage` and `htmlMessage`, but you
really should make your own, distinctive messages. If you want to get going
quickly, in order to use our defaults, provide the following fields instead:

- `name`: the name of your website or service.
- `confirmUrl`: `function(emailToken)`, returns the URL at which you register
  that the email address does belong to the session. The default for this is
  something that returns `https://127.0.0.1/login?token=…`.

`confirmEmail(token, emailToken, function(error, token, session, oldSession))`
should get called from the URL provided to `proveEmail()`. `emailToken` should
be the token extracted from the URL. Since the URL is probably accessed from the
same browser as the user first logged in, it may be sending its identification,
which you can pass through `token`. If it comes from a different computer or
browser, we give that new device a token in the callback, so that we may
recognize it in the future, and we remember that it is connected to the email
address. In that particular case, `oldSession` refers to the session that asked
for an email verification, and `session` to the session linked to the devices
from which the verification was made.

Unless there is an error, *you should set the user's token to the callback's
`token` parameter*, as it may have changed by this operation.

`authenticate(cookieToken, function(error, authenticated, session))` can be
called for every request that require authentication. The browser that sends a
`cookieToken` (a bit of a misnomer, since it doesn't have to be from a cookie)
is authenticated in our system. If we recognize it, `authenticated` is true, and
`session` is sure to be defined. Then, `session` is the browser's session. Note
that it does not mean that the email was verified. Use `session.emailVerified()`
if you want to know.

`logout(cookieToken, function(error))` deletes the Session associated with the
cookieToken. It is not strictly needed (you can simply delete the client's
cookie / local token, for instance), but it ensures that the server doesn't hold
data about Sessions that were destroyed.

`deleteSession(sessionId, function(error))` deletes the Session associated with
that id. Removing that session prevents the corresponding device from
authenticating, effectively logging it out. It can be useful to use (instead of
the more convenient `logout()`) for facilities that log out devices remotely.

`deleteAccount(email, function(error))` deletes all Sessions and information
associated to an email address.

The **Session** has the following methods and fields. You should not modify
those fields.

- `id` is a String containing a unique identifier for that session.
- `email` contains the session's claimed email address, which links it to all
  other sessions from the same email address.
- `emailVerified()` returns true if we know the session is linked to the email
  address.
- `createdAt`: Date at which the session was created.
- `lastAuth`: Date at which the session last connected to us.
- `hash`: identifies the type of one-way function used, as a String.
- `token`: hashed random data identifying a session.
- `proofCreatedAt`: Date when the proof to verify an email was created.
- `proofHash`, `proofToken`: see `hash` and `token`, for the verification token.

# Description

The shadow directory contains the tokens of all identities.
Each device is authenticated independently with a session.
(For instance, with a secure httpOnly cookie containing the token.)
Identities are determined by an email address.
They are linked to all sessions that have confirmed that email address.

Confirmation of an email address happens by sending an email with a link like
`https://example.com/login/?email=<email>&token=<base64>`.
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
email, logs out from the current computer. That only destroys the local cookie,
and the server's associated session.

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

- Detecting logging request spamming
- Allow user-defined storage primitives for the Registry
