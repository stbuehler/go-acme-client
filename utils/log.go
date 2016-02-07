package utils

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"unicode"
)

type LogLevel int

const (
	DEBUG   LogLevel = iota
	INFO    LogLevel = iota
	WARNING LogLevel = iota
	ERROR   LogLevel = iota
)

var CurrentLogLevel = WARNING

type setLogLevel LogLevel

const flagLogLevelSetDebug = setLogLevel(DEBUG)
const flagLogLevelSetInfo = setLogLevel(INFO)

var notBool = errors.New("Not a boolean")

func (lvl setLogLevel) String() string {
	if CurrentLogLevel == LogLevel(lvl) {
		return "true"
	} else {
		return "false"
	}
}

func (lvl setLogLevel) Set(v string) error {
	if v == "true" {
		CurrentLogLevel = LogLevel(lvl)
	} else if v != "false" {
		return notBool
	}
	return nil
}

func (lvl setLogLevel) Value() interface{} {
	return CurrentLogLevel == LogLevel(lvl)
}

func (lvl setLogLevel) IsBoolFlag() bool {
	return true
}

func AddLogFlags(flagset *flag.FlagSet) {
	flagset.Var(flagLogLevelSetDebug, "d", "debug logging")
	flagset.Var(flagLogLevelSetInfo, "v", "verbose logging")
}

func Debugf(format string, v ...interface{}) {
	if CurrentLogLevel <= DEBUG {
		log.Printf("DEBUG: "+format, v...)
	}
}

func Infof(format string, v ...interface{}) {
	if CurrentLogLevel <= INFO {
		log.Printf("INFO: "+format, v...)
	}
}

func Warningf(format string, v ...interface{}) {
	if CurrentLogLevel <= WARNING {
		log.Printf("WARNING: "+format, v...)
	}
}

func Errorf(format string, v ...interface{}) {
	if CurrentLogLevel <= ERROR {
		log.Printf("ERROR: "+format, v...)
	}
}

func Fatalf(format string, v ...interface{}) {
	log.Fatalf("FATAL: "+format, v...)
}

func DebugLogHttpRequest(req *HttpRequest, hReq *http.Request) {
	if CurrentLogLevel <= DEBUG {
		msg := fmt.Sprintf("DEBUG: HTTP request: %s %s\n", req.Method, req.URL)
		for key, values := range hReq.Header {
			for _, value := range values {
				msg += fmt.Sprintf("\t%s: %s\n", key, value)
			}
		}
		msg += "\t\n"

		contentType := req.Headers.ContentType
		if 0 == len(contentType) || strings.Contains(contentType, "text") || strings.Contains(contentType, "json") {
			if nil != req.Body {
				for _, line := range strings.Split(string(req.Body), "\n") {
					msg += "\t" + strings.TrimRightFunc(line, unicode.IsSpace) + "\n"
				}
			}
		} else {
			msg += fmt.Sprintf("\t<not showing possibly binary data for Content-Type %s", contentType)
		}
		log.Print(msg)
	}
}

// fetch response data (if you're intrested in it) before calling this, and pass it along
func DebugLogHttpResponse(resp *HttpResponse) {
	if CurrentLogLevel <= DEBUG {
		msg := fmt.Sprintf("DEBUG: HTTP response: %s\n", resp.Status)
		for key, values := range resp.RawResponse.Header {
			for _, value := range values {
				msg += fmt.Sprintf("\t%s: %s\n", key, value)
			}
		}
		msg += "\t\n"

		contentType := resp.ContentType
		if 0 == len(contentType) || strings.Contains(contentType, "text") || strings.Contains(contentType, "json") {
			if nil == resp.Body {
				var err error
				resp.Body, err = ioutil.ReadAll(resp.RawResponse.Body)
				if nil != err {
					Errorf("failed reading HTTP response data: %s", err)
				}
			}
			for _, line := range strings.Split(string(resp.Body), "\n") {
				msg += "\t" + strings.TrimRightFunc(line, unicode.IsSpace) + "\n"
			}
		} else {
			msg += fmt.Sprintf("\t<not showing possibly binary data for Content-Type %s", contentType)
		}
		log.Print(msg)
	}
}
