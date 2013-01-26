/*
 * Authomato :: authentication proxy
 * author: Karol Kuczmarski "Xion" <karol.kuczmarski@gmail.com>
 */

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	startServer()
}

// Starts the authomato server
func startServer() {
	http.HandleFunc("/hello", helloHandler)
	http.ListenAndServe(":8080", nil)
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

var oauthProviders OAuthProviders
var oauthConsumers OAuthConsumers

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
