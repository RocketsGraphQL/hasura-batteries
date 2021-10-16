package routes

import (
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"
	"golang.org/x/crypto/bcrypt"
)

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

type User struct {
	ID       string
	Email    string
	Password string
}

type SignupResponse struct {
	*User
	Token   string
	Elapsed int
}

type SigninRequest struct {
	*User
}

type SigninResponse struct {
	*User
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

type GetUserHasuraResponse struct {
	Data struct {
		Users []struct {
			Email string `json:"email"`
			ID    string `json:"id"`
			Name  string `json:"name"`
		} `json:"users"`
	} `json:"data"`
}

func NewUserCreatedResponse(user *User, token string) *SignupResponse {
	resp := &SignupResponse{
		User:  user,
		Token: token,
	}

	return resp
}

func UserSigninResponse(user *User) *SigninResponse {
	resp := &SigninResponse{
		User: user,
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

type UserDetails struct {
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

func generateHasuraClaimsData(user UserDetails) (JWTData, error) {
	jwtData := JWTData{
		Sub:   user.Sub,
		Name:  user.Name,
		Admin: user.Admin,
		Hasura: HasuraClaims{
			Claims: map[string]interface{}{
				"x-hasura-allowed-roles": [2]string{
					"manager",
					"user",
				},
				"x-hasura-default-role": "user",
				"x-hasura-user-id":      user.Id,
			},
		},
	}

	return jwtData, nil
}

func getHasuraJWT(user UserDetails) string {

	jwtData, err := generateHasuraClaimsData(user)
	if err != nil {
		log.Fatal("Fucked generating jwt data")
	}
	claims := map[string]interface{}{
		"sub":   jwtData.Sub,
		"name":  jwtData.Name,
		"admin": jwtData.Admin,
		"iat":   1516239022,
		"https://hasura.io/jwt/claims": map[string]interface{}{
			"x-hasura-allowed-roles": jwtData.Hasura.Claims["x-hasura-allowed-roles"],
			"x-hasura-default-role":  jwtData.Hasura.Claims["x-hasura-default-role"],
			"x-hasura-user-id":       jwtData.Hasura.Claims["x-hasura-user-id"],
		},
	}
	signinKey := "If it is able to parse any of the above successfully, then it will use that parsed time to refresh/refetch the JWKs again. If it is unable to parse, then it will not refresh the JWKs"
	tokenAuth := jwtauth.New("HS256", []byte(signinKey), nil)
	log.Println("tokenAuth", tokenAuth)
	_, tokenString, _ := tokenAuth.Encode(claims)

	return tokenString
}

func ChiSignupHandler(w http.ResponseWriter, r *http.Request) {
	data := &SignupRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &User{
		Email:    data.Email,
		Password: data.Password,
	}

	newUser, err := dbNewUser(user)
	if err != nil {
		// user is likely present
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	userDetails := UserDetails{
		Id:    newUser.ID,
		Email: newUser.Email,
		Role:  "user",
		Sub:   "1234567890",
		Name:  newUser.Name,
		Admin: false,
	}
	tokenString := getHasuraJWT(userDetails)
	token := tokenString
	if err != nil {
		log.Fatal(err)
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	createdUser := &User{
		ID:    newUser.ID,
		Email: newUser.Email,
	}
	c := http.Cookie{
		Name:     "jwt",
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, &c)
	c = http.Cookie{
		Name:     "user_id",
		Value:    newUser.ID,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(w, &c)
	render.Status(r, http.StatusCreated)
	render.Render(w, r, NewUserCreatedResponse(createdUser, token))
}

func ChiSigninHandler(w http.ResponseWriter, r *http.Request) {

	data := &SigninRequest{}

	if err := render.Bind(r, data); err != nil {
		render.Render(w, r, ErrInvalidRequest(err))
		return
	}

	user := &User{
		Email:    data.Email,
		Password: data.Password,
	}

	isOk, err := dbCheckUser(user)
	if err != nil {
		// there was an error in the query
		// most likely user not found in db
		render.Render(w, r, ErrRender(err))
		return
	}
	if isOk {
		user, err := dbGetUser(user)
		if err != nil {
			err = errors.New("User somehow not found")
			render.Render(w, r, ErrRender(err))
		}
		createdUser := &User{
			ID:    user.ID,
			Email: user.Email,
		}

		userDetails := UserDetails{
			Id:    user.ID,
			Email: user.Email,
			Role:  "user",
			Sub:   "1234567890",
			Name:  user.Name,
			Admin: false,
		}
		tokenString := getHasuraJWT(userDetails)
		c := http.Cookie{
			Name:     "jwt",
			Value:    tokenString,
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
		}
		http.SetCookie(w, &c)
		c = http.Cookie{
			Name:     "user_id",
			Value:    user.ID,
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
		}
		http.SetCookie(w, &c)
		render.Status(r, http.StatusCreated)
		render.Render(w, r, UserSigninResponse(createdUser))
	} else {
		err1 := errors.New("Invalid credentials")
		render.Render(w, r, ErrRender(err1))
	}
}
