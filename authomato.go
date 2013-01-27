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
	oauthConsumers OAuthConsumers
	oauthSessions  OAuthSessions = make(OAuthSessions)

	callbackPrefix string
)

func main() {
	port := flag.Int("port", 8080, "specify port that the server will listen on")
	domain := flag.String("domain", "127.0.0.1", "specify the server domain for callback URLs")
	https := flag.Bool("https", false, "whether callback URLs should use HTTPS instead of HTTP")
	flag.Parse()

	log.Printf("Initializing Authomato v%s...", VERSION)

	// parse the names of configuration files if provided
	var provFile string = "./oauth_providers.json"
	var consFile string = "./oauth_consumers.json"
	if flag.NArg() > 0 {
		if flag.NArg() > 1 {
			consFile = flag.Arg(1)
		}
		provFile = flag.Arg(0)
	}

	// load OAuth providers and consumers
	if providers, err := loadOAuthProviders(provFile); err != nil {
		log.Printf("Error while reading OAuth providers from %s: %+v", provFile, err)
	} else if consumers, err := loadOAuthConsumers(consFile, providers); err != nil {
		log.Printf("Error while reading OAuth consumers from %s: %+v", consFile, err)
	} else {
		oauthConsumers = consumers
	}
	log.Printf("Loaded %d OAuth consumer(s)", len(oauthConsumers))

	// construct URL prefix for auth. callbacks coming back to the server
	var proto string
	if *https {
		proto = "https"
	} else {
		proto = "http"
	}
	callbackPrefix = fmt.Sprintf("%s://%s:%d", proto, *domain, *port)
	log.Printf("HTTP callbacks will be routed to %s/", callbackPrefix)

	startServer(*port)
}

// Server startup

func startServer(port int) {
	seedRandomGenerator()
	setupRequestHandlers()
	setupSignalHandlers()

	log.Printf("Listening on port %d...", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func seedRandomGenerator() {
	rand.Seed(time.Now().UTC().UnixNano())
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

	// generate unique ID for this session
	var sid string
	for sid == "" || oauthSessions[sid] != nil {
		sid = randomString(24, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}

	requestToken, url, err := consumer.GetRequestTokenAndUrl(
		fmt.Sprintf("%s/oauth/callback?sid=%s", callbackPrefix, sid))
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
	fmt.Fprintf(w, "%s %s", sid, url)
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
		session.Error = fmt.Errorf("oauth_verifier not found in callback request")
		http.Error(w, "no oauth_verifier found", http.StatusForbidden)
		return
	}

	accessToken, err := session.Consumer.AuthorizeToken(session.RequestToken, code)
	if err != nil {
		session.Error = fmt.Errorf("cannot obtain access token: %+v", err)
		http.Error(w, "cannot obtain access token", http.StatusInternalServerError)
		return
	}

	session.AccessToken = accessToken
	session.Error = nil
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
			fmt.Fprintf(w, "%s %s", session.AccessToken.Token, session.AccessToken.Secret)
			return
		}
		if session.Error != nil {
			fmt.Fprintf(w, "error: %+v", session.Error)
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
	Error        error
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
