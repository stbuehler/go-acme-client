package command_certificate_batch

import (
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"os"
	"strings"
	"time"
)

var certificate_batch_flags = flag.NewFlagSet("certificate-batch", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyRSA
var filePrefix string

func init() {
	certificate_batch_flags.IntVar(&rsabits, "rsa-bits", 2048, "Number of bits to generate the RSA key with (if selected)")
	certificate_batch_flags.Var(&curve, "curve", "Elliptic curve to generate ECDSA key with (if selected), one of P-256, P-384, P-521")
	certificate_batch_flags.Var(&keyType, "key-type", "Key type to generate, RSA or ECDSA")
	certificate_batch_flags.StringVar(&filePrefix, "prefix", "", "Prefix for generated <name-key.pem>, <name-cert.pem>, <name.url> files")
	command_base.AddStorageFlags(certificate_batch_flags)
	utils.AddLogFlags(certificate_batch_flags)
}

func Run(UI ui.UserInterface, args []string) {
	certificate_batch_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	listValidAuths, err := reg.AuthorizationInfosWithStatus(types.AuthorizationStatus("valid"))
	if nil != err {
		utils.Fatalf("Couldn't list valid authorizations: %s", err)
	}

	validAuths := make(map[string]bool)
	var validDomains []string

	for dnsName, _ := range listValidAuths {
		validAuths[dnsName] = true
		validDomains = append(validDomains, dnsName)
	}

	if 0 == len(validDomains) {
		utils.Fatalf("You don't have any valid authorizations.")
	}

	privKeyPrompt, _ := UI.PasswordPromptOnce("Enter private key password")

	for _, arg := range certificate_batch_flags.Args() {
		markSelectedDomains := make(map[string]bool)
		var selectedDomains []string
		for _, elem := range strings.Split(arg, ",") {
			elem = strings.TrimSpace(elem)
			if 0 != len(elem) && !markSelectedDomains[elem] {
				selectedDomains = append(selectedDomains, elem)
				markSelectedDomains[elem] = true
			}
		}

		if 0 == len(selectedDomains) {
			continue
		}

		name := selectedDomains[0]
		if '@' == name[0] {
			name = name[1:]
			selectedDomains = selectedDomains[1:]
		}
		if 0 == len(name) {
			utils.Fatalf("Invalid emtpy name for certificate")
			panic(nil)
		}

		overwrite := false

		if existingCert, err := reg.LoadCertificate(name); nil != err {
			utils.Fatalf("Loading certificate with name %#v failed: %v", name, err)
		} else if nil != existingCert {
			expires := existingCert.Certificate().Certificate.NotAfter
			prompt := fmt.Sprintf("Certificate with name %#v already exists (expires in %s). Replace it? [y/N] ", name, utils.FormatDuration(expires.Sub(time.Now())))
			if result, err := UI.Prompt(prompt); nil != err {
				utils.Fatalf("Prompt failed: %v", err)
			} else if result == "Y" || result == "y" {
				overwrite = true
				newName := name + "#" + expires.Format(time.RFC3339)
				if err := existingCert.SetName(newName); nil != err {
					utils.Fatalf("Couldn't change name of existing certificate %#v to %#v", name, newName)
				}
			} else {
				UI.Messagef("Skipping certificate %#v", name)
				continue
			}
		}

		for _, domain := range selectedDomains {
			if !validAuths[domain] {
				utils.Fatalf("Unknown domain %#v, cannot create certificate", domain)
				panic(nil)
			}
		}

		basename := filePrefix + name
		privKeyFilename := basename + "-key.pem"
		certFilename := basename + "-cert.pem"
		urlFilename := basename + ".url"

		var privKey interface{}

		if certFile, err := os.Open(certFilename); nil == err {
			certFile.Close()
			if overwrite {
				if err := os.Remove(certFilename); nil != err {
					utils.Fatalf("Couldn't remove old certificate file %#v", certFilename)
				}
			} else {
				UI.Messagef("Certificate %#v for %s already exists, skipping", certFilename, name)
				continue
			}
		}
		if urlFile, err := os.Open(urlFilename); nil == err {
			urlFile.Close()
			if overwrite {
				if err := os.Remove(urlFilename); nil != err {
					utils.Fatalf("Couldn't remove old certificate file %#v", urlFilename)
				}
			} else {
				UI.Messagef("URL file %#v for %s already exists, skipping", urlFilename, name)
				continue
			}
		}

		if privKeyFile, err := os.Open(privKeyFilename); os.IsNotExist(err) {
			UI.Messagef("Generating private key for certificate %s", name)
			if privKey, err = utils.CreatePrivateKey(keyType, curve, &rsabits); nil != err {
				utils.Fatalf("Couldn't create private key for certificate %s: %v", name, err)
				panic(nil)
			}
			if privKeyBlock, err := utils.EncodePrivateKey(privKey); nil != err {
				utils.Fatalf("Couldn't serialize private key for %s: %v", name, err)
				panic(nil)
			} else if privKeyFile, err := os.OpenFile(privKeyFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); nil != err {
				utils.Fatalf("Couldn't create private key file for %s at %#v", name, privKeyFilename)
				panic(nil)
			} else if err := pem.Encode(privKeyFile, privKeyBlock); nil != err {
				privKeyFile.Close()
				utils.Fatalf("Couldn't write private key file for %s to %#v", name, privKeyFilename)
				panic(nil)
			} else {
				privKeyFile.Close()
			}
		} else if nil != err {
			utils.Fatalf("Couldn't open private key file %#v for reading: %v", privKeyFilename, err)
			panic(nil)
		} else {
			if privKey, err = utils.LoadFirstPrivateKey(privKeyFile, privKeyPrompt); nil != err {
				utils.Fatalf("Couldn't read private key from file %#v: %v", privKeyFilename, err)
				panic(nil)
			}
			privKeyFile.Close()
		}

		csr, err := utils.MakeCertificateRequest(utils.CertificateRequestParameters{
			PrivateKey: privKey,
			DNSNames:   selectedDomains,
		})
		if nil != err {
			utils.Fatalf("Couldn't create certificate request: %s", err)
		}

		utils.Debugf("CSR:\n%s", pem.EncodeToMemory(csr))

		cert, err := reg.NewCertificate(name, *csr)
		if nil != err {
			utils.Fatalf("Certificate request failed: %s", err)
			panic(nil)
		}

		if err := cert.SetPrivateKey(privKey); nil != err {
			utils.Errorf("Couldn't store private key: %s", err)
		}

		certData := cert.Certificate()
		UI.Messagef("New certificate for %s is available at %s (DER encoded)", name, certData.Location)

		if urlFile, err := os.OpenFile(urlFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); nil != err {
			utils.Fatalf("Couldn't create URL file for %s at %#v", name, urlFilename)
			panic(nil)
		} else if _, err := urlFile.WriteString(certData.Location + "\n"); nil != err {
			urlFile.Close()
			os.Remove(urlFilename)
			utils.Fatalf("Couldn't write URL file for %s to %#v", name, urlFilename)
			panic(nil)
		} else {
			urlFile.Close()
		}

		if certFile, err := os.OpenFile(certFilename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); nil != err {
			utils.Fatalf("Couldn't create certificate file for %s at %#v", name, certFilename)
			panic(nil)
		} else if err := pem.Encode(certFile, utils.CertificateToPem(certData.Certificate)); nil != err {
			certFile.Close()
			os.Remove(certFilename)
			utils.Fatalf("Couldn't write certificate for %s to %#v", name, certFilename)
			panic(nil)
		} else {
			certFile.Close()
		}
	}
}
