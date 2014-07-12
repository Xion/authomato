/*
 * Authomato :: authentication proxy
 * author: Karol Kuczmarski "Xion" <karol.kuczmarski@gmail.com>
 *
 * This program is free software, see LICENSE file for details.
 */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
    "strconv"
    "sync"
    "time"

	oauth "github.com/mrjones/oauth"
)

const serverName = "authomato"
const version = "0.0.2"

var (
	port   = flag.Int("port", 8080, "specify port that the server will listen on")
	domain = flag.String("domain", "127.0.0.1", "specify the server domain for callback URLs")
	https  = flag.Bool("https", false, "whether callback URLs should use HTTPS instead of HTTP")
)

var (
	oauthConsumers OAuthConsumers
	oauthSessions  OAuthSessions = makeOAuthSessions()

	callbackPrefix string
)

func main() {
	flag.Parse()

	log.Printf("Initializing Authomato v%s...", version)

	// parse the names of configuration files if provided
	var provFile string = "./oauth_providers.json"
	var consFile string = "./oauth_consumers.json"
	if flag.NArg() > 0 {
		provFile = flag.Arg(0)
	}
	if flag.NArg() > 1 {
		consFile = flag.Arg(1)
	}

	// load OAuth providers and consumers
	providers, err := loadOAuthProviders(provFile)
	if err != nil {
		log.Fatalf("Error while reading OAuth providers from %s: %v", provFile, err)
	}
	consumers, err := loadOAuthConsumers(consFile, providers)
	if err != nil {
		log.Fatalf("Error while reading OAuth consumers from %s: %v", consFile, err)
	}
	oauthConsumers = consumers
	log.Printf("Loaded %d OAuth consumer(s)", len(oauthConsumers))

	// construct URL prefix for auth. callbacks coming back to the server
	proto := "http"
	if *https {
		proto = "https"
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
    type RequestHandler func(http.ResponseWriter, *http.Request)
    withResponseHeaders := func(h RequestHandler) RequestHandler {
        return func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Server", fmt.Sprintf("%s v%s", serverName, version))
            h(w, r)
        }
    }

	http.HandleFunc("/oauth/start", withResponseHeaders(handleOAuthStart))
	http.HandleFunc("/oauth/callback", withResponseHeaders(handleOAuthCallback))
	http.HandleFunc("/oauth/poll", withResponseHeaders(handleOAuthPoll))
}

func setupSignalHandlers() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	go func() {
		sig := <-ch
		log.Printf("Caught %s signal, terminating...", sig)
		os.Exit(0)
	}()
}

// Request handlers

func handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("app")
	if len(name) == 0 {
		http.Error(w, "'app' paramater missing", http.StatusBadRequest)
		return
	}
	consumer, ok := oauthConsumers[name]
	if !ok {
		http.Error(w, "invalid app: "+name, http.StatusNotFound)
		return
	}

	sid := oauthSessions.AllocateId()
	requestToken, url, err := consumer.GetRequestTokenAndUrl(
		fmt.Sprintf("%s/oauth/callback?sid=%s", callbackPrefix, sid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save the session info and return ID + URL for the user
	oauthSessions.Put(sid, &OAuthSession{
		Id:           sid,
		StartedAt:    time.Now(),
		Consumer:     consumer,
		RequestToken: requestToken,
		Channel:      make(chan bool, 1), // for completion signal when doing long poll
	})
	fmt.Fprintf(w, "%s %s", sid, url)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	sid := r.FormValue("sid")
	if len(sid) == 0 {
		http.Error(w, "'sid' missing", http.StatusBadRequest)
		return
	}
	session, ok := oauthSessions.Get(sid)
	if !ok {
		http.Error(w, "invalid session ID: "+sid, http.StatusNotFound)
		return
	}
	code := r.FormValue("oauth_verifier")
	if len(code) == 0 {
		session.Error = fmt.Errorf("oauth_verifier not found in callback request")
		http.Error(w, "no oauth_verifier found", http.StatusForbidden)
		return
	}

	accessToken, err := session.Consumer.AuthorizeToken(session.RequestToken, code)
	if err != nil {
		session.Error = fmt.Errorf("cannot obtain access token: %v", err)
		http.Error(w, "cannot obtain access token", http.StatusInternalServerError)
		return
	}

	session.AccessToken = accessToken
	session.Error = nil
	session.Channel <- true
}

func handleOAuthPoll(w http.ResponseWriter, r *http.Request) {
	sid := r.FormValue("sid")
	if len(sid) == 0 {
		http.Error(w, "'sid' missing", http.StatusBadRequest)
		return
	}
	session, ok := oauthSessions.Get(sid)
	if !ok {
		http.Error(w, "invalid session ID: "+sid, http.StatusNotFound)
		return
	}

    // determine how we are to wait in this particular poll request
    var waitTime int64
	wait := r.FormValue("wait")
    if len(wait) == 0 {
        waitTime = 0
    } else if wait == "true" {
        waitTime = int64(^uint64(0) >> 1) // MaxInt64
    } else {
        waitTime, err := strconv.Atoi(wait)
        if err != nil || waitTime < 0 {
            http.Error(w, "invalid wait value: "+wait, http.StatusBadRequest)
            return
        }
    }

    start := time.Now().Unix()
	for {
		if session.AccessToken != nil {
			fmt.Fprintf(w, "%s %s", session.AccessToken.Token, session.AccessToken.Secret)
			return
		}
		if session.Error != nil {
			fmt.Fprintf(w, "error: %v", session.Error)
			return
		}

        // if the wait time was exceeded, end the request
        now := time.Now().Unix()
        if now - start >= waitTime {
			http.Error(w, "", http.StatusContinue)
			return
		}
		<-session.Channel
	}
}

// Configuration loaders

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
	return providers, nil
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

// Data structures

type OAuthProviders map[string]*oauth.ServiceProvider // indexed by name
type OAuthConsumers map[string]*oauth.Consumer        // indexed by name

type OAuthSession struct {
	Id           string
	StartedAt    time.Time
	Consumer     *oauth.Consumer
	RequestToken *oauth.RequestToken
	AccessToken  *oauth.AccessToken
	Error        error
	Channel      chan bool
}

type OAuthSessions struct {
	sync.RWMutex
	m map[string]*OAuthSession // indexed by ID
}

func makeOAuthSessions() OAuthSessions {
	return OAuthSessions{m: make(map[string]*OAuthSession)}
}

func (s OAuthSessions) Get(k string) (*OAuthSession, bool) {
	s.RLock()
	defer s.RUnlock()
	v, ok := s.m[k]
	return v, ok
}

func (s OAuthSessions) Put(k string, v *OAuthSession) {
	s.Lock()
	defer s.Unlock()
	s.m[k] = v
}

func (s OAuthSessions) Add(k string, v *OAuthSession) bool {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.m[k]; ok {
		return false // already exists, can't add new
	}
	s.m[k] = v
	return true
}

func (s OAuthSessions) AllocateId() string {
	const length = 24
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	for {
		sid := randomString(length, chars)
		if s.Add(sid, nil) {
			return sid
		}
	}
	return "" // unreachable
}

// Utility functions

func randomString(length int, chars string) string {
	b := &bytes.Buffer{}
	for i := 0; i < length; i++ {
		b.WriteByte(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
