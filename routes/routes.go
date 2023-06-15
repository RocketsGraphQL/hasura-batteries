package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/stripe/stripe-go/v72"
)

func writeJSON(w http.ResponseWriter, v interface{}, err error) {
	var respVal interface{}
	if err != nil {
		msg := err.Error()
		var serr *stripe.Error
		if errors.As(err, &serr) {
			msg = serr.Msg
		}
		w.WriteHeader(http.StatusBadRequest)
		var e errResp
		e.Error.Message = msg
		respVal = e
	} else {
		respVal = v
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(respVal); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("json.NewEncoder.Encode: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := io.Copy(w, &buf); err != nil {
		log.Printf("io.Copy: %v", err)
		return
	}
}

// Interface to hold all the authentication methods
func AuthRoutes() chi.Router {
	r := chi.NewRouter()

	r.Post("/login", func(w http.ResponseWriter, req *http.Request) {
		ChiSigninHandler(w, req)
	})
	r.Post("/signup", func(w http.ResponseWriter, req *http.Request) {
		ChiSignupHandler(w, req)
	})
	r.Post("/refresh-token", func(w http.ResponseWriter, req *http.Request) {
		ChiRefreshTokenHandler(w, req)
	})

	r.Post("/github/secrets", func(w http.ResponseWriter, req *http.Request) {
		ChiGithubSecretsSet(w, req)
	})

	r.Get("/github/callback", func(w http.ResponseWriter, req *http.Request) {
		ChiGithubCallback(w, req)
	})

	r.Get("/github/client", func(w http.ResponseWriter, req *http.Request) {
		ChiGithubClient(w, req)
	})

	r.Post("/google/secrets", func(w http.ResponseWriter, req *http.Request) {
		ChiGoogleSecretsSet(w, req)
	})

	r.Get("/google/callback", func(w http.ResponseWriter, req *http.Request) {
		ChiGoogleCallback(w, req)
	})

	r.Get("/google/client", func(w http.ResponseWriter, req *http.Request) {
		ChiGoogleClient(w, req)
	})

	r.Post("/facebook/secrets", func(w http.ResponseWriter, req *http.Request) {
		ChiFacebookSecretsSet(w, req)
	})

	r.Get("/facebook/callback", func(w http.ResponseWriter, req *http.Request) {
		ChiFacebookCallback(w, req)
	})

	r.Get("/facebook/client", func(w http.ResponseWriter, req *http.Request) {
		ChiFacebookClient(w, req)
	})

	r.Get("/tokens", func(w http.ResponseWriter, req *http.Request) {
		ChiTokensHandler(w, req)
	})

	r.Post("/sendotp", func(w http.ResponseWriter, req *http.Request) {
		ChiSendOTPHandler(w, req)
	})

	r.Post("/signin-with-otp", func(w http.ResponseWriter, req *http.Request) {
		ChiSignInViaOTPHandler(w, req)
	})

	return r
}

// Interface to hold all the stripe methods
func StripeRoutes() chi.Router {
	r := chi.NewRouter()

	r.Post("/create-customer", func(w http.ResponseWriter, req *http.Request) {
		// Get the token
		// If error, return 400
		// Create a customer on Stripe
		// And add cus_id -> user_id
		// in DB
		HandleCreateNewStripeCustomer(w, req)
	})
	r.Post("/purchase", func(w http.ResponseWriter, req *http.Request) {

	})
	r.Post("/bootstrap-stripe", func(w http.ResponseWriter, req *http.Request) {

	})
	return r
}
