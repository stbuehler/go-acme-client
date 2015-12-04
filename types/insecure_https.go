package types

import (
	"crypto/tls"
	"net/http"
)

var insecureHttpsClient *http.Client

func getInsecureHttpsClient() *http.Client {
	if nil == insecureHttpsClient {
		insecureHttpsClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
	return insecureHttpsClient
}
