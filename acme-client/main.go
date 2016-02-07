package main

import (
	"github.com/stbuehler/go-acme-client/command_authorize"
	"github.com/stbuehler/go-acme-client/command_authorize_batch"
	"github.com/stbuehler/go-acme-client/command_authorize_import"
	"github.com/stbuehler/go-acme-client/command_certificate"
	"github.com/stbuehler/go-acme-client/command_certificate_batch"
	"github.com/stbuehler/go-acme-client/command_certificate_get"
	"github.com/stbuehler/go-acme-client/command_register"
	"github.com/stbuehler/go-acme-client/ui"
	"os"
)

func main() {
	ui.InitCLI()

	if len(os.Args) <= 1 {
		println("Existing sub commands: ")
		println("\tregister: create account")
		println("\tauthorize: authorize account to create certificates for domain")
		println("\tauthorize-batch: batch authorize domains")
		println("\tauthorize-import: import authorizations")
		println("\tcertificate: show and edit certificates")
		println("\tcertificate-batch: batch create certificates")
		println("\tcertificate-get: create single certificate")
		os.Exit(1)
	} else {
		switch os.Args[1] {
		case "register":
			command_register.Run(ui.CLI, os.Args[2:])
		case "authorize":
			command_authorize.Run(ui.CLI, os.Args[2:])
		case "authorize-batch":
			command_authorize_batch.Run(ui.CLI, os.Args[2:])
		case "authorize-import":
			command_authorize_import.Run(ui.CLI, os.Args[2:])
		case "certificate":
			command_certificate.Run(ui.CLI, os.Args[2:])
		case "certificate-get":
			command_certificate_get.Run(ui.CLI, os.Args[2:])
		case "certificate-batch":
			command_certificate_batch.Run(ui.CLI, os.Args[2:])
		default:
			println("Unknown subcommand: " + os.Args[1])
			os.Exit(1)
		}
	}
}
