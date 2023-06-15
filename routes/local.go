package routes

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"golang.org/x/crypto/bcrypt"
	"rocketsgraphql.app/mod/AuthService"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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
