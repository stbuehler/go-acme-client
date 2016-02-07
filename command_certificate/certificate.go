package command_certificate

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strings"
	"time"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)
var arg_set_name string
var arg_check_ocsp bool

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
	register_flags.StringVar(&arg_set_name, "set-name", "", "Set certificate name")
	register_flags.BoolVar(&arg_check_ocsp, "check-ocsp", false, "Check OCSP status")
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	if len(register_flags.Args()) > 1 {
		utils.Fatalf("Cannot edit/show more than one certificate")
	}

	editMode := len(arg_set_name) > 0 || arg_check_ocsp

	if 0 == len(register_flags.Args()) {
		if editMode {
			utils.Fatalf("Require a certificate name or location to edit a certificate")
		}

		certs, err := reg.CertificateInfos()
		if nil != err {
			utils.Fatalf("Couldn't load certificate list: %s", err)
		}
		UI.Message("Certificate list")
		for _, certData := range certs {
			UI.Messagef("\tCertificate %#v from %s (DER encoded)", certData.Name, certData.Location)
			if nil != certData.Certificate {
				UI.Messagef("\t\tCommon Name: %s", certData.Certificate.Subject.CommonName)
				UI.Messagef("\t\tAlternative Domain Names: %v", strings.Join(certData.Certificate.DNSNames, ","))
				UI.Messagef("\t\tExpires: %v (in %v)", certData.Certificate.NotAfter, utils.FormatDuration(certData.Certificate.NotAfter.Sub(time.Now())))
			}
			if 0 != len(certData.LinkIssuer) {
				UI.Messagef("\t\tIssued by %s", certData.LinkIssuer)
			}
		}
	} else {
		locationOrName := register_flags.Arg(0)
		cert, err := reg.LoadCertificate(locationOrName)
		if nil != err {
			utils.Fatalf("Couldn't load certificate: %s", err)
		} else if nil == cert {
			utils.Fatalf("Couldn't find certificate")
		}
		UI.Messagef("Showing certificate %s", locationOrName)
		certData := cert.Certificate()

		UI.Messagef("\tCertificate %#v from %s (DER encoded)", certData.Name, certData.Location)
		if nil != certData.Certificate {
			UI.Messagef("\t\tCommon Name: %s", certData.Certificate.Subject.CommonName)
			UI.Messagef("\t\tAlternative Domain Names: %v", strings.Join(certData.Certificate.DNSNames, ","))
			UI.Messagef("\t\tExpires: %v (in %v)", certData.Certificate.NotAfter, utils.FormatDuration(certData.Certificate.NotAfter.Sub(time.Now())))
		}
		if 0 != len(certData.LinkIssuer) {
			UI.Messagef("\t\tIssued by %s", certData.LinkIssuer)
		}

		if editMode {
			if len(arg_set_name) > 0 {
				if err := cert.SetName(arg_set_name); nil != err {
					utils.Fatalf("Couldn't set name to %#v: %v", arg_set_name, err)
				}
			}

			if arg_check_ocsp {
				if status, err := CheckOCSP(certData); nil != err {
					UI.Messagef("Couldn't check OCSP status: %v", err)
				} else {
					UI.Messagef("OCSP status: %s", status)
					if status == Revoked && !certData.Revoked {
						if err := cert.SetRevoked(true); nil != err {
							utils.Fatalf("Couldn't set revoked to true", err)
						}
					}
				}
			}
		} else {
			UI.Messagef("%s", pem.EncodeToMemory(utils.CertificateToPem(certData.Certificate)))
			if nil != certData.PrivateKey {
				UI.Messagef("%s", pem.EncodeToMemory(certData.PrivateKey))
			}
		}
	}
}
