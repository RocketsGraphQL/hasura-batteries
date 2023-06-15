package routes

import "github.com/go-chi/render"

func ErrInvalidRequest(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 400,
		StatusText:     "Invalid request.",
		ErrorText:      err.Error(),
	}
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

func ErrRender(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 422,
		StatusText:     "Error rendering response.",
		ErrorText:      err.Error(),
	}
}

func GetGithubCredentialsUpdatedResponse() *GithubCredentialsUpdatedResponse {
	resp := &GithubCredentialsUpdatedResponse{
		message: "Github credentials updated",
	}
	return resp
}
