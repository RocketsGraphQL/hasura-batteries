package routes

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

type CreateNewCustomerInput struct {
	Email string
}

type QueryCustomersResponse struct {
	Customers []struct {
		Email    string `json:"email"`
		StripeID string `json:"stripe_id"`
	} `json:"Customers"`
}

type InsertCustomersResponse struct {
	InsertCustomers struct {
		Returning []struct {
			Email    string `json:"email"`
			StripeID string `json:"stripe_id"`
		} `json:"returning"`
		AffectedRows int `json:"affected_rows"`
	} `json:"insert_Customers"`
}

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

type Access struct {
	AccessToken string `json:"access_token"`
	Scope       string
}

type errResp struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}
