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
	"net/http"
)

var (
	oauthConsumers OAuthConsumers
)

func main() {
	port := flag.Int("port", 8080, "specify port that the server will listen on")
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
		log.Printf("Error while reading OAuth providers from %s: %+v", provFile, err)
	} else if consumers, err := loadOAuthConsumers(consFile, providers); err != nil {
		log.Printf("Error while reading OAuth consumers from %s: %+v", consFile, err)
	} else {
		oauthConsumers = consumers
	}
	log.Printf("Loaded %d OAuth consumer(s)", len(oauthConsumers))

	startServer(*port)
}

// Setup HTTP handlers and start the authomato server
func startServer(port int) {
	http.HandleFunc("/hello", helloHandler)

	log.Printf("Listening on %d...", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// Handlers

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello world!")
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

type OAuthProviders map[string]OAuthProvider
type OAuthConsumers map[string]OAuthConsumer

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
		res[p.Name] = p
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
		res[c.Name] = c
	}
	return res, nil
}
