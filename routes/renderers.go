package routes

import (
	"errors"
	"net/http"

	"github.com/go-chi/render"
)

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

func (rd *SignupResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	rd.Elapsed = 10
	return nil
}

func (rd *SigninResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	return nil
}

func (rd *RefreshTokenResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	return nil
}

func (rd *ClientDetailsResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	return nil
}

func (u *SignupRequest) Bind(r *http.Request) error {
	// u.User is nil if no User fields are sent in the request. Return an
	// error to avoid a nil pointer dereference.
	if u.User == nil {
		return errors.New("missing required Article fields.")
	}
	// a.User is nil if no Userpayload fields are sent in the request. In this app
	// this won't cause a panic, but checks in this Bind method may be required if
	// a.User or futher nested fields like a.User.Name are accessed elsewhere.

	// just a post-process after a decode..
	u.User.ID = "" // unset the protected ID
	// a.Article.Title = strings.ToLower(a.Article.Title) // as an example, we down-case
	return nil
}

func (u *SigninRequest) Bind(r *http.Request) error {
	// u.User is nil if no User fields are sent in the request. Return an
	// error to avoid a nil pointer dereference.
	if u.User == nil {
		return errors.New("missing required Article fields.")
	}
	// a.User is nil if no Userpayload fields are sent in the request. In this app
	// this won't cause a panic, but checks in this Bind method may be required if
	// a.User or futher nested fields like a.User.Name are accessed elsewhere.

	// just a post-process after a decode..
	u.User.ID = "" // unset the protected ID
	// a.Article.Title = strings.ToLower(a.Article.Title) // as an example, we down-case
	return nil
}

func (u *RefreshTokenRequest) Bind(r *http.Request) error {
	// u.User is nil if no User fields are sent in the request. Return an
	// error to avoid a nil pointer dereference.
	// if u.User == nil {
	// 	return errors.New("missing required Article fields.")
	// }
	// a.User is nil if no Userpayload fields are sent in the request. In this app
	// this won't cause a panic, but checks in this Bind method may be required if
	// a.User or futher nested fields like a.User.Name are accessed elsewhere.

	// just a post-process after a decode..
	// u.User.ID = "" // unset the protected ID
	// a.Article.Title = strings.ToLower(a.Article.Title) // as an example, we down-case
	return nil
}

func (u *VerifyOTPRequest) Bind(r *http.Request) error {
	return nil
}

func (p *ClientCredentials) Bind(r *http.Request) error {
	// u.User is nil if no User fields are sent in the request. Return an
	// error to avoid a nil pointer dereference.
	// if p.Name == "" {
	// 	return errors.New("missing required Article fields.")
	// }
	// a.User is nil if no Userpayload fields are sent in the request. In this app
	// this won't cause a panic, but checks in this Bind method may be required if
	// a.User or futher nested fields like a.User.Name are accessed elsewhere.

	// just a post-process after a decode..
	// u.User.ID = "" // unset the protected ID
	// a.Article.Title = strings.ToLower(a.Article.Title) // as an example, we down-case
	return nil
}

func (rd *GithubCredentialsUpdatedResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	return nil
}
