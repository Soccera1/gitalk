# gitalk

`gitalk` is a small instant-message style prototype that uses git as the message
store. Messages are ordinary plaintext files committed through libgit2, with
GPGME producing the detached OpenPGP signature embedded into each commit's
`gpgsig` header.
Trust after tree edits is represented by signed attestation commits:

- the original sender signs the message commit by creating it;
- the server can verify that the current plaintext hash still matches the hash
  recorded when the message was sent, then commit a signed server attestation;
- until the sender returns and signs a user attestation, the message is shown as
  `unverified`;
- once both server and sender attestations exist and the hash still matches, the
  message is shown as `verified`;
- if the plaintext hash changes, the message is shown as `tampered`.

This is a prototype. It relies on your local GPG configuration for real
cryptographic commit signatures, so configure a usable secret key before use.

## Build

```sh
make
```

## Usage

Create or prepare a chat repository:

```sh
./gitalk-server init server
./gitalk-client init alice
```

Start the server:

```sh
./gitalk-server serve server 7777
```

Clients can ping the server very frequently. The default loop interval is 250 ms:

```sh
./gitalk-client ping-loop alice 127.0.0.1 7777
```

Send a signed message:

```sh
./gitalk-client send alice bob "hello from git"
```

List messages and trust state:

```sh
./gitalk-client list alice
```

After history/tree changes, the server checks unchanged plaintext and co-signs:

```sh
./gitalk-server verify server
```

When a user returns online, their client verifies and co-signs their messages:

```sh
./gitalk-client verify alice
```

All commands operate in the current git repository. `send`, `gitalk-server verify`,
and `gitalk-client verify` create signed commit objects with libgit2 and fail if
GPG signing is not configured.
