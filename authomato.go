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
	"time"

	oauth "github.com/mrjones/oauth"
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

	// parse the names of configuration files if provided
	var provFile, consFile string
	if flag.NArg() > 0 {
		if flag.NArg() > 1 {
			consFile = flag.Arg(1)
		} else {
			consFile = "./oauth_consumers.json"
		}
		provFile = flag.Arg(0)
	} else {
		provFile = "./oauth_providers.json"
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

	// remember server details and start it
	if *https {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}
	serverDomain = *domain
	startServer(*port)
}

// Setup HTTP handlers and start the authomato server
func startServer(port int) {
	http.HandleFunc("/oauth/start", handleOAuthStart)
	http.HandleFunc("/oauth/callback", handleOAuthCallback)
	http.HandleFunc("/oauth/poll", handleOAuthPoll)

	log.Printf("Listening on port %d...", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// Handlers

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

	// talk to the OAuth provider and obtain request token
	c := oauth.NewConsumer(consumer.Key, consumer.Secret, oauth.ServiceProvider{
		RequestTokenUrl:   consumer.Provider.RequestTokenUrl,
		AuthorizeTokenUrl: consumer.Provider.AuthorizeUrl,
		AccessTokenUrl:    consumer.Provider.AccessTokenUrl,
	})
	requestToken, url, err := c.GetRequestTokenAndUrl(
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

	// TODO: eliminate need for this data juggling by using oauth lib types directly
	c := oauth.NewConsumer(session.Consumer.Key, session.Consumer.Secret, oauth.ServiceProvider{
		RequestTokenUrl:   session.Consumer.Provider.RequestTokenUrl,
		AuthorizeTokenUrl: session.Consumer.Provider.AuthorizeUrl,
		AccessTokenUrl:    session.Consumer.Provider.AccessTokenUrl,
	})
	accessToken, err := c.AuthorizeToken(session.RequestToken, code)
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
			_ = <-session.Channel
		} else {
			http.Error(w, "", http.StatusContinue)
			return
		}
	}
}

// Configuration data

type OAuthProvider struct {
	Name            string
	RequestTokenUrl string
	AuthorizeUrl    string
	AccessTokenUrl  string
}

type OAuthConsumer struct {
	Name     string
	Provider *OAuthProvider
	Key      string
	Secret   string
}

type OAuthSession struct {
	Id           string
	StartedAt    time.Time
	Consumer     *OAuthConsumer
	RequestToken *oauth.RequestToken
	AccessToken  *oauth.AccessToken
	Error        bool // TODO: make it more fine grained
	Channel      chan bool
}

type OAuthProviders map[string]*OAuthProvider // indexed by name
type OAuthConsumers map[string]*OAuthConsumer // indexed by name
type OAuthSessions map[string]*OAuthSession   // indexed by ID

func loadOAuthProviders(filename string) (OAuthProviders, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var providers []OAuthProvider
	err = json.Unmarshal(b, &providers)
	if err != nil {
		return nil, err
	}

	res := make(OAuthProviders)
	for _, p := range providers {
		res[p.Name] = &p
	}
	return res, nil
}

func loadOAuthConsumers(filename string, oauthProviders OAuthProviders) (OAuthConsumers, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var consumers []OAuthConsumer
	err = json.Unmarshal(b, &consumers)
	if err != nil {
		return nil, err
	}

	res := make(OAuthConsumers)
	for _, c := range consumers {
		res[c.Name] = &c
	}
	return res, nil
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
