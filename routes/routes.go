package routes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/google/go-github/github"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"rocketsgraphql.app/mod/AuthService"
	"rocketsgraphql.app/mod/types"
)

var background = context.Background()
var googleOauthConfig *oauth2.Config

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

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

type VerifyOTPRequest struct {
	*User
	Otp string
}

type Tokens struct {
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}
type User struct {
	ID       string
	Email    string
	Password string
	Phone    string
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

func (u *VerifyOTPRequest) Bind(r *http.Request) error {
	return nil
}

type Claims struct {
	Id    string
	Email string
	Role  string
	Sub   string
	Name  string
	Phone string
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
	CallbackURL  string
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
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	redirectUrl := os.Getenv("GITHUB_REDIRECT_URL") + "?rgraphRefreshToken=" + refreshTokenCookie.Value + "&rgraphAccessToken=" + accessTokenCookie.Value
	render.Status(r, http.StatusCreated)
	http.Redirect(w, r, redirectUrl, http.StatusMovedPermanently)
	//render.Render(w, r, UserSignupResponse(createdUser, accessToken, refresh))
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

type GoogleUserDetails struct {
	ID    string
	Name  string
	Email string
}

func ChiGoogleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Here is Google callback!!")
	var googleUserDetails = &GoogleUserDetails{}
	// Read oauthState from Cookie
	// oauthState, _ := r.Cookie("oauthstate")

	// if r.FormValue("state") != oauthState.Value {
	// 	log.Println("invalid oauth google state")
	// 	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	// 	return
	// }

	data, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// GetOrCreate User in your db.
	// Redirect or response with a token.
	// More code .....
	// fmt.Fprintf(w, "UserInfo: %s\n", data)

	err = json.Unmarshal(data, googleUserDetails)
	// Add user via passwordless login
	var provider types.Provider = types.GOOGLE
	newUser := &AuthService.User{
		Email: string(googleUserDetails.Email),
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
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	redirectUrl := os.Getenv("GOOGLE_REDIRECT_URL") + "?rgraphRefreshToken=" + refreshTokenCookie.Value + "&rgraphAccessToken=" + accessTokenCookie.Value
	// render.Status(r, http.StatusCreated)
	http.Redirect(w, r, redirectUrl, http.StatusMovedPermanently)
}

// FacebookUserDetails is struct used for user details
type FacebookUserDetails struct {
	ID    string
	Name  string
	Email string
}

func ChiFacebookCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("Here is Facebook callback!!")
	var fbUserDetails FacebookUserDetails
	var clientId = os.Getenv("FACEBOOK_APP_ID")
	var clientSecret = os.Getenv("FACEBOOK_APP_SECRET")
	var redirectUrl = os.Getenv("FACEBOOK_REDIRECT_URI")
	code := r.URL.Query().Get("code")
	// values := url.Values{"client_id": {clientId}, "client_secret": {clientSecret}, "redirect_uri": {redirectUrl}, "code": {code}, "accept": {"json"}}

	var url = "https://graph.facebook.com/v14.0/oauth/access_token?client_id=" + clientId + "&client_secret=" + clientSecret + "&redirect_uri=" + redirectUrl + "&code=" + code
	req, _ := http.NewRequest("GET", url, nil)

	log.Printf("request: ", req)
	req.Header.Set(
		"Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Print(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Retrieving access token failed: ", resp.StatusCode, resp, clientId, clientSecret)
		return
	}
	var access Access

	if err := json.NewDecoder(resp.Body).Decode(&access); err != nil {
		log.Println("JSON-Decode-Problem: ", err)
		return
	}
	facebookUserDetailsRequest, _ := http.NewRequest("GET", "https://graph.facebook.com/me?fields=id,name,email&access_token="+access.AccessToken, nil)
	facebookUserDetailsResponse, facebookUserDetailsResponseError := http.DefaultClient.Do(facebookUserDetailsRequest)

	if facebookUserDetailsResponseError != nil {
		errors.New("Error occurred while getting information from Facebook")
		return
	}

	decoder := json.NewDecoder(facebookUserDetailsResponse.Body)
	decoderErr := decoder.Decode(&fbUserDetails)
	defer facebookUserDetailsResponse.Body.Close()

	if decoderErr != nil {
		errors.New("Error occurred while getting information from Facebook")
		return
	}
	log.Println("Here is Facebook user!!", fbUserDetails.Email)
	if fbUserDetails.Email == "" {
		return
	}

	// Add user via passwordless login
	var provider types.Provider = types.FACEBOOK
	newUser := &AuthService.User{
		Email: string(fbUserDetails.Email),
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
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		// Not setting this will lead to the cookie
		// being set to the path /api/github
		// we want the cookie to be accessible by the whole backend
		Path:   "/",
		Secure: true,
	}
	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	redirectUrI := os.Getenv("FACEBOOK_REDIRECT_URL") + "?rgraphRefreshToken=" + refreshTokenCookie.Value + "&rgraphAccessToken=" + accessTokenCookie.Value

	render.Status(r, http.StatusCreated)
	http.Redirect(w, r, redirectUrI, http.StatusMovedPermanently)
	return
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

func ChiGoogleSecretsSet(w http.ResponseWriter, r *http.Request) {
	data := &ClientCredentials{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	// Set credentials to the env
	// I think this is the most appropriate
	// way to store client ids
	os.Setenv("GOOGLE_CLIENT_ID", data.ClientId)
	os.Setenv("GOOGLE_CLIENT_SECRET", data.ClientSecret)
	os.Setenv("GOOGLE_CALLBACK_URL", data.CallbackURL)
	os.Setenv("GOOGLE_REDIRECT_URL", data.RedirectURL)

	render.Status(r, http.StatusCreated)
	render.Render(w, r, GetGithubCredentialsUpdatedResponse())
}

func ChiFacebookSecretsSet(w http.ResponseWriter, r *http.Request) {
	data := &ClientCredentials{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	// Set credentials to the env
	// I think this is the most appropriate
	// way to store client ids
	os.Setenv("FACEBOOK_APP_ID", data.ClientId)
	os.Setenv("FACEBOOK_APP_SECRET", data.ClientSecret)

	os.Setenv("FACEBOOK_CALLBACK_URL", data.CallbackURL)
	os.Setenv("FACEBOOK_REDIRECT_URL", data.RedirectURL)

	render.Status(r, http.StatusCreated)
	render.Render(w, r, GetGithubCredentialsUpdatedResponse())
}

func ChiSignupHandler(w http.ResponseWriter, r *http.Request) {
	data := &SignupRequest{}
	fmt.Println("req", r)
	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &AuthService.User{
		Email:    data.Email,
		Password: data.Password,
	}

	newUser, err := AuthService.NewUser(user)
	fmt.Println("data", user.Email, newUser)

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

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(20 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func ChiGoogleClient(w http.ResponseWriter, r *http.Request) {
	googleRedirectUrl := os.Getenv("GOOGLE_CALLBACK_URL")

	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)
	// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  googleRedirectUrl,
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	u := googleOauthConfig.AuthCodeURL(oauthState)
	providerUrl := u
	log.Println("github details: ", providerUrl, googleRedirectUrl)

	render.Render(w, r, ClientDetails(googleRedirectUrl, providerUrl))
}

func ChiFacebookClient(w http.ResponseWriter, r *http.Request) {
	clientId := os.Getenv("FACEBOOK_CLIENT_ID")
	redirectUrl := os.Getenv("FACEBOOK_CALLBACK_URL")
	providerUrl := "https://www.facebook.com/v14.0/dialog/oauth?client_id=" + clientId + "&redirect_uri=" + redirectUrl + "&state={'{st=state123abc,ds=123456789}'}"
	log.Println("github details: ", redirectUrl, providerUrl)

	render.Render(w, r, ClientDetails(redirectUrl, providerUrl))

}

// http://localhost:7000/api/facebook/callback?code=AQCD4HmlqBknSSKqqu4jeaKl7ZfSXg9lMkiLIezkMVFpE8jiLhZ296RlKE2WGCBq0cvSmu8sTVJquPY53WkKgJOViH2VKKjlNBu71VWQyMR1cTpQnY5bZ8377yZgAqlTPMiPEiNX5oicpvnArk8iRAAl8TebU_Qp7OyKCgcOq16a-bW1Uys5pjV7JB2rmouHm1EFiMFMy8B3wt5lhBBGJEcX4FBJ72P_fJS4J-izIEgWt_LXcSaOdOcCrxxiytlyqVDL9WIeyzrGW__NDbNy3P6w7b0gB0qFlGgUDr6CN5hwsoxP40ZbUsWdJzMc_eChm7EdP_DX9_3v0ZMCZ4GVYZsS5QUr8Txy18D_S0JqTL8OH-K9w2pn-im67dOUOySInhc#_=_

func ChiSendOTPHandler(w http.ResponseWriter, r *http.Request) {
	data := &SigninRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &AuthService.User{
		Phone: data.Phone,
	}
	AuthService.OTPLogin(user)
}

func ChiSignInViaOTPHandler(w http.ResponseWriter, r *http.Request) {
	data := &VerifyOTPRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	fmt.Println("data: ", data.Otp)
	user := &AuthService.User{
		Phone: data.Phone,
	}
	// First check if the user exists
	// The user might have logged in already
	// with his mobile number and his session
	// might have expired
	_, err := AuthService.GetUser(user)
	if err != nil {
		// The user is new
		// Insert user
		// Generate tokens
		// and send back the response
		// with 200 OK
		otp := data.Otp
		AuthService.OTPVerify(user, otp)
		// Now if the above verification is
		// successful --> create a new user
		AuthService.NewUserWithOTPLogin(user)
		newUser := &User{
			Phone: data.Phone,
		}
		access, refresh := getTokensForOTPLogin(newUser, r)
		render.Render(w, r, UserSignupResponse(newUser, access, refresh))

	} else {
		// user already exists
		// We just refresh the JWTs
		// and send back the response
		// with 200 OK
		otp := data.Otp
		AuthService.OTPVerify(user, otp)
		// Now if the above verification is
		// successful --> generate new tokens
		access, refresh := getTokensForOTPLogin(&User{
			Phone: data.Phone,
		}, r)
		existing := &User{
			Phone: data.Phone,
		}
		render.Render(w, r, UserSignupResponse(existing, access, refresh))
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
