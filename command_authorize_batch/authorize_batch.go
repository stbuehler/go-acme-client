package command_authorize_batch

import (
	"crypto"
	"flag"
	"github.com/stbuehler/go-acme-client/command_base"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"time"
)

var register_flags = flag.NewFlagSet("register", flag.ExitOnError)
var arg_refresh bool

func init() {
	command_base.AddStorageFlags(register_flags)
	utils.AddLogFlags(register_flags)
	register_flags.BoolVar(&arg_refresh, "refresh", false, "refresh status of locally known authorizations")
}

func Run(UI ui.UserInterface, args []string) {
	register_flags.Parse(args)

	_, _, reg := command_base.OpenStorageFromFlags(UI)
	if nil == reg {
		utils.Fatalf("You need to register first")
	}

	keyhash, err := reg.Registration().SigningKey.GetPublicKey().Thumbprint(crypto.SHA256)
	if nil != err {
		utils.Fatalf("Cannot get SHA256 hash of public key: %v", err)
	}
	UI.Messagef(
		"Make sure requests to your domains of the form http://<domain>/.well-known/acme-challenge/<token> are answered as text/plain with content:\n<token>.%s",
		utils.Base64UrlEncode(keyhash))

	for _, domain := range register_flags.Args() {
		if auth, err := reg.GetAuthorizationByDNS(domain, arg_refresh); nil != err {
			utils.Fatalf("Couldn't load authorization for %v: %v", domain, err)
		} else {
			if nil == auth {
				if auth, err = reg.AuthorizeDNS(domain); nil != err {
					utils.Fatalf("Couldn't get authorization for %v: %s", domain, err)
				}
			}

			// refresh every round
			authData := auth.Authorization()

			if string(authData.Resource.Status) != "" {
				UI.Messagef("Status for %v: %s", domain, authData.Resource.Status)
				continue
			}

			tryingCombs := make(map[int]bool)
			for ndx, challenge := range authData.Resource.Challenges {
				if challenge.GetType() == "http-01" {
					if 0 == len(challenge.GetValidated()) {
						tryingCombs[ndx] = true

						chResp, err := authData.Respond(reg.Registration(), ndx)
						if nil != err {
							utils.Fatalf("Error trying to create response: %s", err)
						} else if nil == chResp {
							panic("http-01 not supported")
						}

						if err = chResp.InitializeResponse(UI); nil != err {
							utils.Fatalf("Failed to initialize response: %s", err)
						}

						// if err = chResp.ShowInstructions(UI); nil != err {
						// 	utils.Fatalf("Failed to complete challenge: %s", err)
						// 	continue
						// }
						if err = chResp.Verify(); nil != err {
							utils.Fatalf("Failed to verify challenge: %s", err)
						}

						// update refreshes auth automatically
						if err = auth.UpdateChallenge(chResp); nil != err {
							UI.Messagef("Failed to update challenge: %s", err)
							continue
						}
					}
				} else if 0 != len(challenge.GetValidated()) {
					tryingCombs[ndx] = true
				}
			}
			possible := false
			for _, comb := range authData.Resource.Combinations {
				possibleComb := true
				for _, combElem := range comb {
					if !tryingCombs[combElem] {
						possibleComb = false
						break
					}
				}
				if possibleComb {
					possible = true
					break
				}
			}

			if !possible {
				UI.Messagef("Cannot batch authorize %v due to unsupported challenge types", domain)
			}

			for i := 0; i < 10; i++ {
				// refresh every round
				authData = auth.Authorization()

				if string(authData.Resource.Status) != "" {
					UI.Messagef("Status for %v: %s", domain, authData.Resource.Status)
					break
				} else if 0 == i {
					UI.Messagef("Waiting for auhorization for %v to become valid", domain)
				}

				time.Sleep(time.Second)
				if err := auth.Refresh(); nil != err {
					utils.Errorf("Couldn't update authorization for %v: %s", domain, err)
				}
			}

			if string(authData.Resource.Status) == "" {
				UI.Messagef("Waiting for auhorization for %v timed out", domain)
			}
		}
	}
}
