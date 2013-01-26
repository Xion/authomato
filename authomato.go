/*
 * Authomato :: authentication proxy
 * author: Karol Kuczmarski "Xion" <karol.kuczmarski@gmail.com>
 */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"time"

	oauth "github.com/mrjones/oauth"
)

const (
	VERSION = "0.0.1"
)

var (
	serverProtocol string
	serverDomain   string

	oauthConsumers OAuthConsumers
	oauthSessions  OAuthSessions = make(OAuthSessions)
)

func main() {
	port := flag.Int("port", 8080, "specify port that the server will listen on")
	domain := flag.String("domain", "127.0.0.1", "specify the server domain for callback URLs")
	https := flag.Bool("https", false, "whether callback URLs should use HTTPS instead of HTTP")
	flag.Parse()

	log.Printf("Initializing Authomato v%s...", VERSION)

	// parse the names of configuration files if provided
	var provFile, consFile string
	if flag.NArg() > 0 {
		if flag.NArg() > 1 {
			consFile = flag.Arg(1)
		} else {
			consFile = "./oauth_consumers.json"
			log.Printf("No OAuth consumers file specified -- using default: %s", consFile)
		}
		provFile = flag.Arg(0)
	} else {
		provFile = "./oauth_providers.json"
		log.Printf("No OAuth providers file specified -- using default: %s", provFile)
	}

	// load OAuth providers and consumers
	if providers, err := loadOAuthProviders(provFile); err != nil {
		log.Printf("Error while reading OAuth providers (%+v)", err)
	} else if consumers, err := loadOAuthConsumers(consFile, providers); err != nil {
		log.Printf("Error while reading OAuth consumers (%+v)", err)
	} else {
		oauthConsumers = consumers
	}
	log.Printf("Loaded %d OAuth consumer(s)", len(oauthConsumers))

	// remember server details
	if *https {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}
	serverDomain = *domain
	log.Printf("HTTP callbacks will use address %s://%s/", serverProtocol, serverDomain)

	startServer(*port)
}

// Server startup

func startServer(port int) {
	setupRequestHandlers()
	setupSignalHandlers()

	log.Printf("Listening on port %d...", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func setupRequestHandlers() {
	http.HandleFunc("/oauth/start", handleOAuthStart)
	http.HandleFunc("/oauth/callback", handleOAuthCallback)
	http.HandleFunc("/oauth/poll", handleOAuthPoll)
}

func setupSignalHandlers() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	go func() {
		for {
			sig := <-ch
			log.Printf("Caught %s signal, terminating...", sig)
			os.Exit(0)
		}
	}()
}

// Request handlers

func handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("app")
	if len(name) == 0 {
		http.Error(w, "'app' missing", http.StatusBadRequest)
		return
	}
	consumer := oauthConsumers[name]
	if consumer == nil {
		http.Error(w, "invalid app: "+name, http.StatusNotFound)
		return
	}

	// generate ID for this session
	var sid string
	for sid == "" || oauthSessions[sid] != nil {
		sid = randomString(24, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}

	requestToken, url, err := consumer.GetRequestTokenAndUrl(
		fmt.Sprint("%s://%s/oauth/callback?sid=%s", serverProtocol, serverDomain, sid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save the session info and return ID + URL for the user
	oauthSessions[sid] = &OAuthSession{
		Id:           sid,
		StartedAt:    time.Now(),
		Consumer:     consumer,
		RequestToken: requestToken,
		Channel:      make(chan bool, 1), // for completion signal when doing long poll
	}
	fmt.Printf("%s %s", sid, url)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	if len(sid) == 0 {
		http.Error(w, "'sid' missing", http.StatusBadRequest)
		return
	}
	session := oauthSessions[sid]
	if session == nil {
		http.Error(w, "invalid session ID: "+sid, http.StatusNotFound)
		return
	}
	code := r.URL.Query().Get("oauth_verifier")
	if len(code) == 0 {
		session.Error = true
		http.Error(w, "no oauth_verifier found", http.StatusForbidden)
		return
	}

	accessToken, err := session.Consumer.AuthorizeToken(session.RequestToken, code)
	if err == nil {
		session.Error = true
		http.Error(w, "cannot obtain access token", http.StatusInternalServerError)
		return
	}

	session.AccessToken = accessToken
	session.Channel <- true
}

func handleOAuthPoll(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	if len(sid) == 0 {
		http.Error(w, "'sid' missing", http.StatusBadRequest)
		return
	}
	session := oauthSessions[sid]
	if session == nil {
		http.Error(w, "invalid session ID: "+sid, http.StatusNotFound)
		return
	}

	wait := r.URL.Query().Get("wait") == "true"
	for {
		if session.AccessToken != nil {
			// success: we can return the access token
			fmt.Fprintf(w, "%s %s", session.AccessToken.Token, session.AccessToken.Secret)
		} else if session.Error {
			fmt.Fprint(w, "error")
			return
		}

		if wait {
			<-session.Channel
		} else {
			http.Error(w, "", http.StatusContinue)
			return
		}
	}
}

// Data structures

type OAuthSession struct {
	Id           string
	StartedAt    time.Time
	Consumer     *oauth.Consumer
	RequestToken *oauth.RequestToken
	AccessToken  *oauth.AccessToken
	Error        bool // TODO: make it more fine grained
	Channel      chan bool
}

type OAuthProviders map[string]*oauth.ServiceProvider // indexed by name
type OAuthConsumers map[string]*oauth.Consumer        // indexed by name
type OAuthSessions map[string]*OAuthSession           // indexed by ID

func loadOAuthProviders(filename string) (OAuthProviders, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// parse the JSON into generic map
	var data map[string]interface{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	// construct oauth.ServiceProvider structures
	providers := make(OAuthProviders)
	for k, v := range data {
		p := v.(map[string]interface{})
		providers[k] = &oauth.ServiceProvider{
			RequestTokenUrl:   p["requestTokenUrl"].(string),
			AuthorizeTokenUrl: p["authorizeUrl"].(string),
			AccessTokenUrl:    p["accessTokenUrl"].(string),
		}
	}
	return providers, err
}

func loadOAuthConsumers(filename string, oauthProviders OAuthProviders) (OAuthConsumers, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// parse the JSON into generic map
	var data map[string]interface{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	// resolve references to OAuth providers and construct result
	consumers := make(OAuthConsumers)
	for k, v := range data {
		c := v.(map[string]interface{})

		provName := c["provider"].(string)
		if len(provName) == 0 {
			return nil, fmt.Errorf("unspecified provider for consumer: %s", k)
		}
		provider := oauthProviders[provName]
		if provider == nil {
			return nil, fmt.Errorf("unknown provider: %s", provName)
		}
		key, secret := c["key"].(string), c["secret"].(string)
		if len(key) == 0 || len(secret) == 0 {
			return nil, fmt.Errorf("unspecified key and/or secret for consumer: %s", k)
		}

		consumers[k] = oauth.NewConsumer(key, secret, *provider)
	}
	return consumers, nil
}

// Utility functions

func randomString(length int, chars string) string {
	res := ""
	for i := 0; i < length; i++ {
		k := rand.Intn(len(chars))
		res += string(chars[k])
	}
	return res
}
