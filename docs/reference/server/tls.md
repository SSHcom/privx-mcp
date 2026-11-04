# TLS (HTTPS)

The server supports TLS for secure connections. It is required when MCP clients refuse non-localhost HTTP URLs.

The certificates below are meant for development and test deployments. In production, use a certificate from an official Certificate Authority (CA).

## Related documents

- [MCP server configuration](SERVER.md)
- [MCP client configuration](../clients/CLIENTS.md)

## Generating certificates with mkcert

[mkcert](https://github.com/FiloSottile/mkcert) issues certificates from a local CA that it also installs into the trust stores.

```bash
# 1. Install the local CA into system and application trust stores.
#    This step is required once per machine. It ensures Node.js-based
#    clients (Kiro, Cursor) trust certificates issued by mkcert.
mkcert -install

# 2. Generate a certificate for your server hostname(s).
mkcert -cert-file ~/.ssh/mcp-tls-cert.pem \
       -key-file ~/.ssh/mcp-tls-key.pem \
       example-mcp.demo.net localhost 127.0.0.1

# 3. Restrict key file permissions.
chmod 600 ~/.ssh/mcp-tls-key.pem
```

## Generating a self-signed certificate with OpenSSL

```bash
# 1. Generate a certificate for your server hostname(s).
openssl req -x509 -newkey rsa:2048 \
  -keyout ~/.ssh/mcp-tls-key.pem \
  -out ~/.ssh/mcp-tls-cert.pem \
  -days 365 -nodes \
  -subj "/CN=example-mcp.demo.net" \
  -addext "subjectAltName=DNS:example-mcp.demo.net,DNS:localhost,IP:127.0.0.1"

# 2. Restrict key file permissions.
chmod 600 ~/.ssh/mcp-tls-key.pem
```

A self-signed certificate must be trusted before clients accept it.

**macOS**:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.ssh/mcp-tls-cert.pem
```

**Linux**: distributions and applications do not share one certificate trust store or installation mechanism. Configure either your distribution's system trust store or the individual client to trust `~/.ssh/mcp-tls-cert.pem`. Useful search terms:

- Install custom CA certificate system trust store on Linux
- Trust self-signed certificate on Linux

## Server configuration

Add the TLS paths to `privx-mcp-config.toml`:

```toml
[server]
public_url = "https://example-mcp.demo.net:8181"
tls_cert_file = "/home/you/.ssh/mcp-tls-cert.pem"
tls_key_file = "/home/you/.ssh/mcp-tls-key.pem"
```

The server starts with HTTPS when both `tls_cert_file` and `tls_key_file` are set. If either is omitted, it starts with plain HTTP.
