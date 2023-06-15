package routes

import (
	"errors"
	"net/http"

	"github.com/go-chi/render"
	"rocketsgraphql.app/mod/AuthService"
)

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
		verificationStatus, err := AuthService.OTPVerify(user, otp)
		// Now if the above verification is
		// successful --> create a new user
		if err != nil || verificationStatus != "approved" {
			// There was an error
			// Either we dint send correct parameters
			// Or the OTP was invalid
			// Most likely its the latter
			// So Dont login this guy
			// And return error
			errInvalid := errors.New("Invalid credentials")
			render.Render(w, r, ErrRender(errInvalid))
		} else {
			AuthService.NewUserWithOTPLogin(user)
			newUser := &User{
				Phone: data.Phone,
			}
			access, refresh := getTokensForOTPLogin(newUser, r)
			render.Render(w, r, UserSignupResponse(newUser, access, refresh))
		}

	} else {
		// user already exists
		// We just refresh the JWTs
		// and send back the response
		// with 200 OK
		otp := data.Otp
		verificationStatus, err := AuthService.OTPVerify(user, otp)
		// Now if the above verification is
		// successful --> generate new tokens
		if err != nil || verificationStatus != "approved" {
			errInvalid := errors.New("Invalid credentials")
			render.Render(w, r, ErrRender(errInvalid))
		} else {
			access, refresh := getTokensForOTPLogin(&User{
				Phone: data.Phone,
			}, r)
			existing := &User{
				Phone: data.Phone,
			}
			render.Render(w, r, UserSignupResponse(existing, access, refresh))
		}

	}
}
