# `mailcloak-bridge`

Transparently encrypt/decrypt email via local [IMAP](https://www.rfc-editor.org/rfc/rfc9051) and [SMTP](https://www.rfc-editor.org/rfc/rfc6409) server that adds [PGP](https://www.openpgp.org/) and [S/MIME](https://en.wikipedia.org/wiki/S/MIME) encryption to any mail provider. It works like [Proton Mail Bridge](https://proton.me/mail/bridge).

Your mail client connects to the bridge, and the bridge connects to your provider. The bridge decrypts incoming mail and encrypts outgoing mail. It uses the keys and rules of [mailcloak](https://github.com/brodyhoskins/mailcloak) for this. The bridge can use the same key directories and `state_dir` as the `mailcloak-encrypt` and `mailcloak-decrypt` filters.

## Usage

```
mailcloak-bridge [-config file] [-version] [-detect address]
```

In your mail client, set the incoming and outgoing servers to the `mailcached` host and ports with TLS. Use your email provider username and password. A JMAP client needs the session URL, like `https://<mailcached host>:<jmap port>/.well-known/jmap`.

## Configuration

See [examples/mailcloak.yaml](file:./examples/mailcloak.yaml).

## License

MIT. See [LICENSE](LICENSE).
