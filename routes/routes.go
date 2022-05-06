package routes

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/google/go-github/github"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"rocketsgraphql.app/mod/AuthService"
	"rocketsgraphql.app/mod/types"
)

var background = context.Background()

// ErrResponse renderer type for handling all sorts of errors.
//
// In the best case scenario, the excellent github.com/pkg/errors package
// helps reveal information on the error, setting it on Err, and in the Render()
// method, using it to set the application-specific error code in AppCode.
type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func ErrInvalidRequest(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 400,
		StatusText:     "Invalid request.",
		ErrorText:      err.Error(),
	}
}

type SignupRequest struct {
	// User *User `json:"user,omitempty"`
	*User
	// ProtectedID string `json:"id"` // override 'id' json to have more control
}

type Tokens struct {
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}
type User struct {
	ID       string
	Email    string
	Password string
}

type SignupResponse struct {
	*User
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
	Elapsed int
}

type SigninRequest struct {
	*User
}

type SigninResponse struct {
	*User
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}

type RefreshTokenResponse struct {
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}

type RefreshTokenRequest struct {
	*Tokens
}

type HasuraInsertUserResponse struct {
	InsertUsers struct {
		Returning []struct {
			Email        string `json:"email"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			Passwordhash string `json:"passwordhash"`
		} `json:"returning"`
	} `json:"insert_users"`
}

type DbNewUserResponse struct {
	Email string `json:"email"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

type HasuraGetUserByEmailResponse struct {
	Users []struct {
		Email        string `json:"email"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		Passwordhash string `json:"passwordhash"`
	} `json:"users"`
}
type DbExistingUserResponse struct {
	Email string `json:"email"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

type DbNewUserError struct {
	message string
}

type CheckUserHasuraResponse struct {
	Data struct {
		Users []struct {
			ID           string `json:"id"`
			Passwordhash string `json:"passwordhash"`
		} `json:"users"`
	} `json:"data"`
}

type ClientDetailsResponse struct {
	ProviderUrl string
	RedirectUrl string
}

func UserSignupResponse(user *User, access string, refresh string) *SignupResponse {
	resp := &SignupResponse{
		User:    user,
		Access:  access,
		Refresh: refresh,
	}

	return resp
}

func UserSigninResponse(user *User, access string, refresh string) *SigninResponse {
	resp := &SigninResponse{
		User:    user,
		Access:  access,
		Refresh: refresh,
	}
	return resp
}

func NewTokensRespose(access string, refresh string) *RefreshTokenResponse {
	resp := &RefreshTokenResponse{
		Access:  access,
		Refresh: refresh,
	}
	return resp
}

func ClientDetails(redirectUrl string, providerUrl string) *ClientDetailsResponse {
	resp := &ClientDetailsResponse{
		ProviderUrl: providerUrl,
		RedirectUrl: redirectUrl,
	}
	return resp
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ErrRender(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 422,
		StatusText:     "Error rendering response.",
		ErrorText:      err.Error(),
	}
}

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

type Claims struct {
	Id    string
	Email string
	Role  string
	Sub   string
	Name  string
	Admin bool
}

type HasuraClaims struct {
	Claims map[string]interface{}
}
type JWTData struct {
	Sub    string
	Name   string
	Admin  bool
	Hasura HasuraClaims
}

type ClientCredentials struct {
	ClientId     string
	ClientSecret string
	RedirectURL  string
}

type GithubCredentialsUpdatedResponse struct {
	message string
}

func (rd *GithubCredentialsUpdatedResponse) Render(w http.ResponseWriter, r *http.Request) error {
	// Pre-processing before a response is marshalled and sent across the wire
	return nil
}

func GetGithubCredentialsUpdatedResponse() *GithubCredentialsUpdatedResponse {
	resp := &GithubCredentialsUpdatedResponse{
		message: "Github credentials updated",
	}
	return resp
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

type Access struct {
	AccessToken string `json:"access_token"`
	Scope       string
}

// Authenticates GitHub Client with provided OAuth access token
func getGitHubClient(accessToken string) *github.Client {
	ctx := background
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func ChiGithubCallback(w http.ResponseWriter, r *http.Request) {
	var clientId = os.Getenv("GITHUB_CLIENT_ID")
	var clientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	code := r.URL.Query().Get("code")
	values := url.Values{"client_id": {clientId}, "client_secret": {clientSecret}, "code": {code}, "accept": {"json"}}

	req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", strings.NewReader(values.Encode()))

	req.Header.Set(
		"Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Print(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Retrieving access token failed: ", resp.StatusCode, clientId, clientSecret)
		return
	}
	var access Access

	if err := json.NewDecoder(resp.Body).Decode(&access); err != nil {
		log.Println("JSON-Decode-Problem: ", err)
		return
	}

	if access.Scope != "user:email" {
		log.Println("Wrong token scope: ", access.Scope)
		return
	}

	client := getGitHubClient(access.AccessToken)

	user, _, err := client.Users.Get(background, "")
	if err != nil {
		log.Println("Could not list user details: ", err)
		return
	}

	emails, _, err := client.Users.ListEmails(background, nil)
	if err != nil {
		log.Println("Could not list user emails: ", err)
		return
	}

	log.Println("User details: ", user, string(*emails[0].Email), os.Getenv("GITHUB_REDIRECT_URL"))

	// Add user via passwordless login
	var provider types.Provider = types.GITHUB
	newUser := &AuthService.User{
		Email: string(*emails[0].Email),
	}
	dbUser, err := AuthService.PasswordlessProviderLogin(provider, newUser)
	if err != nil {
		log.Println("Could not login the user on github")
		ErrInvalidRequest(err)
	}

	// generate tokens for the user as usual
	createdUser := &User{
		ID:    dbUser.ID,
		Email: dbUser.Email,
	}
	accessToken, refresh := getTokens(createdUser, r)
	accessTokenCookie := http.Cookie{
		Name:     "jwt",
		Value:    accessToken,
		Expires:  time.Now().Add(20 * time.Minute),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	render.Status(r, http.StatusCreated)
	http.Redirect(w, r, os.Getenv("GITHUB_REDIRECT_URL"), http.StatusMovedPermanently)
	//render.Render(w, r, UserSignupResponse(createdUser, accessToken, refresh))
}

func ChiGithubSecretsSet(w http.ResponseWriter, r *http.Request) {
	data := &ClientCredentials{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	// Set credentials to the env
	// I think this is the most appropriate
	// way to store client ids
	os.Setenv("GITHUB_CLIENT_ID", data.ClientId)
	os.Setenv("GITHUB_CLIENT_SECRET", data.ClientSecret)
	os.Setenv("GITHUB_REDIRECT_URL", data.RedirectURL)

	render.Status(r, http.StatusCreated)
	render.Render(w, r, GetGithubCredentialsUpdatedResponse())
}

func ChiSignupHandler(w http.ResponseWriter, r *http.Request) {
	data := &SignupRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &AuthService.User{
		Email:    data.Email,
		Password: data.Password,
	}

	newUser, err := AuthService.NewUser(user)
	if err != nil {
		// user is likely present
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	createdUser := &User{
		ID:    newUser.ID,
		Email: newUser.Email,
	}
	access, refresh := getTokens(createdUser, r)
	accessTokenCookie := http.Cookie{
		Name:     "jwt",
		Value:    access,
		Expires:  time.Now().Add(20 * time.Minute),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	render.Status(r, http.StatusCreated)
	render.Render(w, r, UserSignupResponse(createdUser, access, refresh))
}

func ChiSigninHandler(w http.ResponseWriter, r *http.Request) {

	data := &SigninRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &AuthService.User{
		Email:    data.Email,
		Password: data.Password,
	}

	isOk, err := AuthService.CheckUser(user)
	if err != nil {
		// there was an error in the query
		// most likely user not found in db
		render.Render(w, r, ErrRender(err))
		return
	}
	if isOk {
		user, err := AuthService.GetUser(user)
		if err != nil {
			err = errors.New("User somehow not found")
			render.Render(w, r, ErrRender(err))
		}
		existingUser := &User{
			ID:    user.ID,
			Email: user.Email,
		}
		access, refresh := getTokens(existingUser, r)
		accessTokenCookie := http.Cookie{
			Name:     "jwt",
			Value:    access,
			Path:     "/",
			Expires:  time.Now().Add(20 * time.Minute),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}
		refreshTokenCookie := http.Cookie{
			Name:     "refresh",
			Value:    refresh,
			Path:     "/",
			Expires:  time.Now().Add(365 * 24 * time.Hour),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}
		http.SetCookie(w, &accessTokenCookie)
		http.SetCookie(w, &refreshTokenCookie)
		render.Status(r, http.StatusOK)
		render.Render(w, r, UserSigninResponse(existingUser, access, refresh))
	} else {
		errInvalid := errors.New("Invalid credentials")
		render.Render(w, r, ErrRender(errInvalid))
	}
}

func ChiRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	data := &RefreshTokenRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}
	access, refresh, err := refreshToken(data.Refresh)

	if err != nil {
		render.Render(w, r, ErrRender(err))
	}
	accessTokenCookie := http.Cookie{
		Name:     "jwt",
		Value:    access,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)
	render.Status(r, http.StatusOK)
	render.Render(w, r, NewTokensRespose(access, refresh))

}

func ChiTokensHandler(w http.ResponseWriter, r *http.Request) {
	jwtcookie, err := r.Cookie("jwt")
	refreshcookie, err := r.Cookie("jwt")
	if err != nil {
		render.Render(w, r, ErrRender(err))
	}
	render.Render(w, r, NewTokensRespose(jwtcookie.Value, refreshcookie.Value))
}

func ChiGithubClient(w http.ResponseWriter, r *http.Request) {
	githubRedirectUrl := os.Getenv("GITHUB_REDIRECT_URL")
	providerUrl := "https://github.com/login/oauth/authorize?scope=user:email&client_id=" + os.Getenv("GITHUB_CLIENT_ID")
	log.Println("github details: ", githubRedirectUrl, providerUrl)

	render.Render(w, r, ClientDetails(githubRedirectUrl, providerUrl))
}
