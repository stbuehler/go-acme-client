package command_certificate_get

import (
	"encoding/pem"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"os"
	"time"
)

var register_flags = flag.NewFlagSet("certificate-get", flag.ExitOnError)

var rsabits int = 2048
var curve utils.Curve = utils.CurveP521
var keyType utils.KeyType = utils.KeyRSA
var loadPrivKey string

func init() {
	register_flags.IntVar(&rsabits, "rsa-bits", 2048, "Number of bits to generate the RSA key with (if selected)")
	register_flags.Var(&curve, "curve", "Elliptic curve to generate ECDSA key with (if selected), one of P-256, P-384, P-521")
	register_flags.Var(&keyType, "key-type", "Key type to generate, RSA or ECDSA")
	register_flags.StringVar(&loadPrivKey, "import-key", "", "Import private key")
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

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

	var pkey interface{}
	if 0 != len(loadPrivKey) {
		pkeyPrompt, _ := UI.PasswordPromptOnce("Enter private key password")
		if pkeyFile, err := os.Open(loadPrivKey); nil != err {
			utils.Fatalf("%s", err)
		} else if pkey, err = utils.LoadFirstPrivateKey(pkeyFile, pkeyPrompt); nil != err {
			utils.Fatalf("%s", err)
		}
	} else {
		UI.Message("Generating private key for certificate")
		var err error
		if pkey, err = utils.CreatePrivateKey(keyType, curve, &rsabits); nil != err {
			utils.Fatalf("Couldn't create private key for certificate: %s", err)
		}
	}

	markSelectedDomains := make(map[string]bool)
	var selectedDomains []string

	if 0 != len(register_flags.Args()) {
		for _, domain := range register_flags.Args() {
			if 0 == len(domain) {
				continue
			}
			if markSelectedDomains[domain] {
				continue
			}
			markSelectedDomains[domain] = true
			if !validAuths[domain] {
				utils.Fatalf("Unknown domain %#v, not adding - try again", domain)
			}
			selectedDomains = append(selectedDomains, domain)
		}
	}

	if 0 == len(selectedDomains) {
		UI.Messagef("Available domains: %v", validDomains)

		for {
			domain, err := UI.Prompt("Enter domain to add to certificate (empty to end list)")
			if err != nil {
				utils.Fatalf("Couldn't read domain: %s", err)
			}
			if 0 == len(domain) {
				break
			}
			if markSelectedDomains[domain] {
				UI.Messagef("Already selected %#v", domain)
				continue
			}
			markSelectedDomains[domain] = true
			if !validAuths[domain] {
				UI.Messagef("Unknown domain %#v, not adding - try again", domain)
				continue
			}
			selectedDomains = append(selectedDomains, domain)
		}
	}

	if 0 == len(selectedDomains) {
		UI.Message("No domains entered, aborting")
		return
	}

	csr, err := utils.MakeCertificateRequest(utils.CertificateRequestParameters{
		PrivateKey: pkey,
		DNSNames:   selectedDomains,
	})
	if nil != err {
		utils.Fatalf("Couldn't create certificate request: %s", err)
	}

	utils.Debugf("CSR:\n%s", pem.EncodeToMemory(csr))

	name := selectedDomains[0] + "#" + time.Now().Format(time.RFC3339)
	cert, err := reg.NewCertificate(name, *csr)
	if nil != err {
		utils.Fatalf("Certificate request failed: %s", err)
	}

	if err := cert.SetPrivateKey(pkey); nil != err {
		utils.Errorf("Couldn't store private key: %s", err)
	}
	certData := cert.Certificate()

	UI.Messagef("New certificate is available under: %s (DER encoded)", certData.Location)
	if 0 != len(certData.LinkIssuer) {
		UI.Messagef("Issueing certificate available at: %s", certData.LinkIssuer)
	}
	UI.Messagef("%s", pem.EncodeToMemory(utils.CertificateToPem(certData.Certificate)))
	if nil != certData.PrivateKey {
		UI.Messagef("%s", pem.EncodeToMemory(certData.PrivateKey))
	}
}
