# Authomato

A simple OAuth proxy for applications that cannot afford a web browser

## How does it work?

The typical OAuth flow for authorizing an app to access user's account
involves several HTTP requests and requires intercepting redirects.
This is easy for web apps, but might be tricky or outright impossible
for other kinds of applications, especially if the OAuth provider
doesn't support PIN-based authentication.

Authomato can act as middleman for such programs, making the authentication
flow simpler and more convenient to the user. With Authomato,
the process of authorizing an app is very simple:

1. Issue a request to Authomato server with your app (consumer) name.
   You will get a _session ID_ (`sid`) and URL that the user should visit.
2. Display the URL you got or just open the browser. This will allow the user
   to authorize your application.
3. Wait on long poll request until you get the access token. You can also hit
   the server periodically until the authentication flow is complete.

Once you have the access token, you can call the provider's API using
any of the various OAuth client libraries available for almost any language.

## Configuration

First, define the OAuth providers you're using in _oauth\_providers.json_:

    {
        "twitter": {
            requestTokenUrl": "http://twitter.com/oauth/request_token",
            "authorizeUrl": "http://twitter.com/oauth/authenticate",
            "accessTokenUrl": "http://twitter.com/oauth/access_token"
        }
    }

Next, add your consumers ("apps") to _oauth_consumers.json_:

    {
        "mytwitterapp" : {
            "provider": "twitter",
            "key": "<OAuth key for mytwitterapp>",
            "secret": "<OAuth secret for mytwitterapp>"
        }
    }

Finally, run the server:

    $ ./authomato
    2013/01/26 21:12:22 Initializing Authomato v0.0.1...
    2013/01/26 21:12:22 Loaded 1 OAuth consumer(s)
    2013/01/26 21:12:22 HTTP callbacks will be routed to http://127.0.0.1:8080/
    2013/01/26 21:12:22 Listening on port 8080...

## API

All requests use simple HTTP query parameters and return plain text
for maximum interoperability. Error conditions are communicated
as HTTP status codes.

### /oauth/start

Start the OAuth flow.

Query parameters:

* `app`: name of the OAuth consumer ("application"), as defined in _oauth_consumers.json_

Response body contains the following data as plain text, delimited by whitespace:

* session ID (`sid`) identifying this authentication flow
* URL of authorization page that should be displayed to the user

### /oauth/poll

Check the state of OAuth flow, retrieving the access token if available.

Query parameters:

* `sid`: session ID received when starting the flow
* (_optional_) `wait`: `true` if the request should block until authorization is finished

Returns HTTP status 200 (OK) with access token in response body
(token & secret delimited by whitespace).
Returns HTTP status 100 (Continue) if `wait=true` wasn't provided and access token
is not yet available.
