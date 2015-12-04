package types

import (
	"crypto"
	"fmt"
	"github.com/stbuehler/go-acme-client/ui"
	"github.com/stbuehler/go-acme-client/utils"
	"io/ioutil"
	"net/http"
	"strings"
)

const http01Identifier string = "http-01"

type challengeHttp01 struct {
	Resource ResourceChallengeTag `json:"resource"`
	rawChallengeBasic
	Token string `json:"token,omitempty"` // ASCII only
}

func (http01 *challengeHttp01) GetType() string {
	return http01.Type
}

func (http01 *challengeHttp01) GetStatus() string {
	return http01.Status
}

func (http01 *challengeHttp01) GetValidated() string {
	return http01.Validated
}

func (http01 *challengeHttp01) GetURI() string {
	return http01.URI
}

type challengeHttp01Data struct {
	Resource         ResourceChallengeTag `json:"resource"`
	Type             string               `json:"type"`
	KeyAuthorization string               `json:"keyAuthorization"`
}

func (http01Data *challengeHttp01Data) GetType() string {
	return http01Data.Type
}

type challengeHttp01Responding struct {
	registration  *Registration
	dnsIdentifier string
	challenge     challengeHttp01
	data          challengeHttp01Data
}

func (http01 *challengeHttp01) initializeResponse(registration *Registration, authorization *Authorization) (ChallengeResponding, error) {
	keyhash, err := registration.SigningKey.GetPublicKey().Thumbprint(crypto.SHA256)
	if nil != err {
		return nil, err
	}

	responding := challengeHttp01Responding{
		registration:  registration,
		dnsIdentifier: string(authorization.Resource.DNSIdentifier),
		challenge:     *http01,
		data: challengeHttp01Data{
			Type:             http01Identifier,
			KeyAuthorization: http01.Token + "." + utils.Base64UrlEncode(keyhash),
		},
	}

	if oldData := authorization.ChallengesData[http01.GetURI()].chDataImpl; nil != oldData {
		if oldData := oldData.(*challengeHttp01Data); nil != oldData {
			responding.data = *oldData
		}
	}
	return &responding, nil
}

func (responding *challengeHttp01Responding) WellKnownURL() string {
	return fmt.Sprintf(
		"http://%s/.well-known/acme-challenge/%s",
		responding.dnsIdentifier,
		responding.challenge.Token)
}

func (responding *challengeHttp01Responding) ResetResponse() error {
	return nil
}

func (responding *challengeHttp01Responding) InitializeResponse(UI ui.UserInterface) error {
	return nil
}

func (responding *challengeHttp01Responding) ShowInstructions(UI ui.UserInterface) error {
	if _, err := UI.Prompt(fmt.Sprintf(
		"Make the text on the next line available (without quotes) as %s\n%v\nPress enter when done",
		responding.WellKnownURL(), responding.data.KeyAuthorization)); nil != err {
		return err
	}
	return nil
}

func (responding *challengeHttp01Responding) Verify() error {
	httpClient := &http.Client{}
	// TODO: try TLS if port 80 connection fails?

	url := responding.WellKnownURL()
	resp, err := httpClient.Get(url)
	if nil != err {
		return err
	}
	defer resp.Body.Close()
	if 200 != resp.StatusCode {
		return fmt.Errorf("GET %s failed: %s", url, resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if nil != err {
		return err
	}
	contentType := resp.Header.Get("Content-Type")
	contentType = strings.Split(contentType, ";")[0]
	contentType = strings.TrimSpace(contentType)
	if 0 != len(contentType) && "text/plain" != contentType {
		return fmt.Errorf("document at %s has wrong content-type %#v, expected none or text/plain", url, contentType)
	}

	verifyData := strings.TrimSpace(string(body))
	if verifyData != responding.data.KeyAuthorization {
		return fmt.Errorf("content of document at %s doesn't match expected data %s: got %#v", url, responding.data.KeyAuthorization, verifyData)
	}

	return nil
}

func (responding *challengeHttp01Responding) SendPayload() (interface{}, error) {
	return responding.data, nil
}

func (responding *challengeHttp01Responding) ChallengeData() ChallengeData {
	return ChallengeData{chDataImpl: &responding.data}
}

func (responding *challengeHttp01Responding) Challenge() Challenge {
	return Challenge{chImpl: &responding.challenge}
}

func (responding *challengeHttp01Responding) Registration() *Registration {
	return responding.registration
}
