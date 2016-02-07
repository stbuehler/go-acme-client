## Purpose

`acme-client` is an ACME client (the prococol behind https://letsencrypt.org/)
which tries to take away the magic; it needs manual handling of the challenge
response, although it aids the administrator in the process.

The security benefit is that the registration (consisting of a private key) can
be kept offline, instead of keeping it on the live server as intended by the
letsencrypt project.

THIS PROJECT IS STILL EXPERIMENTAL; BUT UPDATES SHOULD NOT BREAK THE
LOCAL STORAGE ANYMORE. KEEPING BACKUPS IS STILL RECOMMENDED.

## Install

(Setup GOPATH first; something like export `GOPATH=$HOME/go`)

	go get github.com/stbuehler/go-acme-client/acme-client

## Usage

For now the binary will put persistent data into `storage.sqlite3` in the
current working directory, so always run it from the same working directory.

### Create registration ("account")

	$GOPATH/bin/acme-client register

The password is used for local encryption of your private key (which is used to sign your requests) and other data.

### Claim one or more domain names:

	$GOPATH/bin/acme-client authorize example.com

It will show various challenges and combinations. You need to satisfy at least on combination (i.e. all challenges part of it).

Select the challenge you want to respond to (`simpleHttp`/`http-01` involves serving a static file, `dvsni`/`tls-sni-01` setting up a "fake" vhost with a SSL certificate), and follow the instructions.

### Batch-clam domain names:

`http-01` has a very nice batchable interface; you need to setup your web server to serve requests of the form `http://domain/.well-known/acme-challenge/<token>` and return a `text/plain` document with the text `<token>.<pubkeyhash>`.

The `<pubkeyhash>` is the SHA256 Thumbprint of your JWS public web key; run

	$GOPATH/bin/acme-client authorize-batch

to see it.

lighttpd2 for example can do this in the config like this:

	if req.path =~ "/.well-known/acme-challenge/([-a-zA-Z0-9_]+)$" {
		respond '%1.url-base64-encoding-of-sha256-thumbprint';
	}

No simply run:

	$GOPATH/bin/acme-client authorize-batch example.com sub.example.com more.example.com

with all the domain names you want to authorize.

### Create a certificate

	$GOPATH/bin/acme-client certificate-get [domains...]

You can give it a private key to use (by default it wil generate a 2048-bit RSA key).

If you don't give any domain names it will ask interactively and show available ones. The first domain name will also be used in the Common Name

In the output will also be a link where you can pull the certificate any time you want; it should automatically provide a refreshed certificate if the old one is getting near the expiry date.
