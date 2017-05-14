package command_certificate

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/model"
	"github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"strings"
	"time"
)

var register_flags = flag.NewFlagSet("certificate", flag.ExitOnError)
var arg_set_name string
var arg_check_ocsp bool
var arg_revoke bool

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
	register_flags.StringVar(&arg_set_name, "set-name", "", "Set certificate name")
	register_flags.BoolVar(&arg_check_ocsp, "check-ocsp", false, "Check OCSP status")
	register_flags.BoolVar(&arg_revoke, "revoke", false, "Revoke certificate")
}

func showInfo(UI ui.UserInterface, certInfo storage_interface.CertificateInfo) {
	UI.Messagef("Certificate %#v from %s (DER encoded)", certInfo.Name, certInfo.Location)
	if nil != certInfo.Certificate {
		UI.Messagef("\tCommon Name: %s", certInfo.Certificate.Subject.CommonName)
		UI.Messagef("\tAlternative Domain Names: %v", strings.Join(certInfo.Certificate.DNSNames, ","))
		UI.Messagef("\tExpires: %v (in %v)", certInfo.Certificate.NotAfter, utils.FormatDuration(certInfo.Certificate.NotAfter.Sub(time.Now())))
	}
	if 0 != len(certInfo.LinkIssuer) {
		UI.Messagef("\tIssued by %s", certInfo.LinkIssuer)
	}
}

func showData(UI ui.UserInterface, certData types.Certificate) {
	UI.Messagef("Certificate %#v from %s (DER encoded)", certData.Name, certData.Location)
	if nil != certData.Certificate {
		UI.Messagef("\tCommon Name: %s", certData.Certificate.Subject.CommonName)
		UI.Messagef("\tAlternative Domain Names: %v", strings.Join(certData.Certificate.DNSNames, ","))
		UI.Messagef("\tExpires: %v (in %v)", certData.Certificate.NotAfter, utils.FormatDuration(certData.Certificate.NotAfter.Sub(time.Now())))
	}
	if 0 != len(certData.LinkIssuer) {
		UI.Messagef("\tIssued by %s", certData.LinkIssuer)
	}
}

func try_load(reg model.RegistrationModel, locationOrName string) model.CertificateModel {
	cert, err := reg.LoadCertificate(locationOrName)
	if nil != err {
		utils.Fatalf("Couldn't load certificate: %s", err)
	}
	return cert
}

func load(reg model.RegistrationModel, locationOrName string) model.CertificateModel {
	cert := try_load(reg, locationOrName)
	if nil == cert {
		utils.Fatalf("Couldn't find certificate")
	}
	return cert
}

func loadAndShow(reg model.RegistrationModel, UI ui.UserInterface, locationOrName string) (model.CertificateModel, types.Certificate) {
	cert := load(reg, locationOrName)
	certData := cert.Certificate()

	showData(UI, certData)

	return cert, certData
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

	have_mode := len(arg_set_name) > 0
	if arg_check_ocsp {
		if have_mode {
			utils.Fatalf("Only one command mode can be given")
		}
		have_mode = true
	}
	if arg_revoke {
		if have_mode {
			utils.Fatalf("Only one command mode can be given")
		}
		have_mode = true
	}

	if len(arg_set_name) > 0 {
		if len(register_flags.Args()) > 1 {
			utils.Fatalf("Cannot edit more than one certificate")
		} else if 0 == len(register_flags.Args()) {
			utils.Fatalf("Require a certificate name or location to edit a certificate")
		}
		cert, _ := loadAndShow(reg, UI, register_flags.Arg(0))

		if err := cert.SetName(arg_set_name); nil != err {
			utils.Fatalf("Couldn't set name to %#v: %v", arg_set_name, err)
		}
	} else if 0 == len(register_flags.Args()) {
		certs, err := reg.CertificateInfos()
		if nil != err {
			utils.Fatalf("Couldn't load certificate list: %s", err)
		}

		if arg_check_ocsp {
			for _, certInfo := range certs {
				showInfo(UI, certInfo)
				if status, err := CheckOCSP(certInfo.LinkIssuer, certInfo.Certificate); nil != err {
					UI.Messagef("Couldn't check OCSP status: %v", err)
				} else {
					UI.Messagef("OCSP status: %s", status)
					if status == Revoked {
						cert := load(reg, certInfo.Name)
						if err := cert.SetRevoked(true); nil != err {
							utils.Fatalf("Couldn't set revoked to true", err)
						}
					}
				}
			}
		} else if arg_revoke {
			UI.Message("Searching for replaced certificates")
			// when a certificate gets renewed, the old one is renamed:
			// '#<timestamp>' gets appended
			for _, certInfo := range certs {
				pos := strings.IndexByte(certInfo.Name, '#')
				if -1 == pos {
					// wasn't replaced
					continue
				}

				newName := certInfo.Name[0:pos]
				newCert := try_load(reg, newName)
				if nil == newCert {
					// no new cert that replaced the old one
					continue
				}
				UI.Messagef("It seems certificate %#v replaced %#v:", newName, certInfo.Name)
				showData(UI, newCert.Certificate())
				showInfo(UI, certInfo)

				if result, err := UI.Prompt("Revoke old certificate? [y/N] "); nil != err {
					utils.Fatalf("Prompt failed: %v", err)
				} else if result == "Y" || result == "y" {
					cert := load(reg, certInfo.Name)
					if err := cert.Revoke(); nil != err {
						utils.Fatalf("Couldn't revoke certificate: %v", err)
					}
				} else {
					UI.Messagef("Not revoking certificate")
				}
			}
		} else {
			UI.Message("Certificate list")
			for _, certInfo := range certs {
				showInfo(UI, certInfo)
			}
		}
	} else {
		for _, arg := range register_flags.Args() {
			cert, certData := loadAndShow(reg, UI, arg)

			if arg_revoke {
				if result, err := UI.Prompt("Really revoke certificate? [y/N] "); nil != err {
					utils.Fatalf("Prompt failed: %v", err)
				} else if result == "Y" || result == "y" {
					if err := cert.Revoke(); nil != err {
						utils.Fatalf("Couldn't revoke certificate: %v", err)
					}
				} else {
					UI.Messagef("Not revoking certificate")
				}
			} else if arg_check_ocsp {
				if status, err := CheckOCSP(certData.LinkIssuer, certData.Certificate); nil != err {
					UI.Messagef("Couldn't check OCSP status: %v", err)
				} else {
					UI.Messagef("OCSP status: %s", status)
					if status == Revoked && !certData.Revoked {
						if err := cert.SetRevoked(true); nil != err {
							utils.Fatalf("Couldn't set revoked to true", err)
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
}
