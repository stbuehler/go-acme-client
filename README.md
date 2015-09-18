## Purpose

`acme-client` is an ACME client (the prococol behind https://letsencrypt.org/)
which tries to take away the magic; it needs manual handling of the challenge
response, although it aids the administrator in the process.

The security benefit is that the registration (consisting of a private key) can
be kept offline, instead of keeping it on the live server as intended by the
letsencrypt project.

THIS PROJECT IS STILL EXPERIMENTAL; EACH UPDATE MIGHT BREAK THE LOCAL STORAGE.

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

Select the challenge you want to respond to (`simpleHttp` involves serving a static file, `dvsni` setting up a "fake" vhost with a SSL certificate), and follow the instructions.

### Create a certificate

	$GOPATH/bin/acme-client certificate

It takes an optional private key, otherwise it will generate one (by default a 2048-bit RSA key).

It will ask interactively for the domain names you want the certificate to be valid for (the first one will also be used in the Common Name).
