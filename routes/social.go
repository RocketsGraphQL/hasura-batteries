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

	"github.com/go-chi/render"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"rocketsgraphql.app/mod/AuthService"
	"rocketsgraphql.app/mod/types"
)

var background = context.Background()
var googleOauthConfig *oauth2.Config

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

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
	var fbUserDetails FacebookUserDetails
	var clientId = os.Getenv("FACEBOOK_APP_ID")
	var clientSecret = os.Getenv("FACEBOOK_APP_SECRET")
	var redirectUrl = os.Getenv("FACEBOOK_REDIRECT_URI")
	code := r.URL.Query().Get("code")
	// values := url.Values{"client_id": {clientId}, "client_secret": {clientSecret}, "redirect_uri": {redirectUrl}, "code": {code}, "accept": {"json"}}

	var url = "https://graph.facebook.com/v14.0/oauth/access_token?client_id=" + clientId + "&client_secret=" + clientSecret + "&redirect_uri=" + redirectUrl + "&code=" + code
	req, _ := http.NewRequest("GET", url, nil)

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

// Authenticates GitHub Client with provided OAuth access token
func getGitHubClient(accessToken string) *github.Client {
	ctx := background
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
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
