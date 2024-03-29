package AuthService

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/machinebox/graphql"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/verify/v2"
	"golang.org/x/crypto/bcrypt"
	"rocketsgraphql.app/mod/gql_strings"
	"rocketsgraphql.app/mod/types"
)

type User struct {
	ID       string
	Email    string
	Password string
	Phone    string
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

type DBNewProviderResponse struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	USERID   string `json:"userid"`
}

type HasuraGetUserByEmailResponse struct {
	Users []struct {
		Email        string `json:"email"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		Passwordhash string `json:"passwordhash"`
	} `json:"users"`
}

type HasuraNewProviderResponse struct {
	InsertProviders struct {
		Returning []struct {
			ID       string `json:"id"`
			Provider string `json:"provider"`
			UserID   string `json:"user_id"`
		} `json:"returning"`
	} `json:"insert_providers"`
}
type DbExistingUserResponse struct {
	Email string `json:"email"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

type DbNewProviderResponse struct {
	ID       string `json:"id"`
	UserId   string `json:"userid"`
	Provider string `json:"provider"`
}

type DbNewUserError struct {
	message string
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GetUser(user *User) (DbExistingUserResponse, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	// HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")
	// query the Hasura query endpoint
	// to get the user by email
	// NOTE: Email is unique
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.GetUserWithPasswordByEmail)
	// set any variables
	request.Var("email", user.Email)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)

	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraGetUserByEmailResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		panic(err)
	}
	users := graphqlResponse.Users

	if len(users) > 0 {
		user := DbExistingUserResponse{
			Email: users[0].Email,
			ID:    users[0].ID,
			Name:  users[0].Name,
		}
		return user, nil
	} else {
		log.Println("Unable to get correct length while inserting new user")
		return DbExistingUserResponse{}, errors.New("Couldn't get the requested user at this time")
	}
}

func NewProviderForUser(user *User, provider types.Provider) (DbNewProviderResponse, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	// query the Hasura query endpoint
	// to put the provider, user pair
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.InsertNewProvider)
	// set any variables
	request.Var("provider", provider.String())
	request.Var("user_id", user.ID)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)
	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraNewProviderResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		panic(err)
	}
	providers := graphqlResponse.InsertProviders.Returning

	log.Println("Created providers for user", providers, user)
	if len(providers) > 0 {
		provider := DbNewProviderResponse{
			ID:       providers[0].ID,
			UserId:   providers[0].UserID,
			Provider: providers[0].Provider,
		}
		return provider, nil
	} else {
		log.Println("Unable to get correct length while inserting new provider for user")
		return DbNewProviderResponse{}, errors.New("Couldn't login the requested user at this time")
	}
}

func NewPasswordlessUser(user *User) (*DbNewUserResponse, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	// query the Hasura query endpoint
	// to put the user, provider by email
	// NOTE: Email is non-unique
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.InsertNewPasswordlessUser)
	// set any variables
	request.Var("email", user.Email)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)

	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraInsertUserResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		panic(err)
	}
	users := graphqlResponse.InsertUsers.Returning
	log.Println("users are new: ", users)
	if len(users) == 0 {
		// This should not happen as we inserted a user
		return nil, errors.New("Unable to retrieve the inserted user at this time")
	}
	return &DbNewUserResponse{
		ID:    users[0].ID,
		Email: users[0].Email,
	}, nil
}

func NewUser(user *User) (*DbNewUserResponse, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")
	fmt.Fprintln(os.Stdout, HASURA_SECRET_KEY)

	// First check if user with that email exists
	isPresent, err := CheckUser(user)
	// if present return an error
	// since emails are unique
	if isPresent {
		return nil, errors.New("A user with that email already exists")
	}
	// If user is new
	// mutate the Hasura query endpoint
	// to insert the user
	// NOTE: Email is unique
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.InsertNewUser)
	// hash password
	hashed, err := HashPassword(user.Password)
	if err != nil {
		log.Fatal("Unable to hash password")
		return nil, errors.New("Unable to hash password")
	}
	// set any variables
	request.Var("email", user.Email)
	request.Var("name", user.Email)
	request.Var("passwordhash", hashed)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)
	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraInsertUserResponse
	log.Println("client run", user.Email)
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		fmt.Println(err)
		panic(err)
	}

	users := graphqlResponse.InsertUsers.Returning
	if len(users) == 0 {
		// This should not happen as we inserted a user
		return nil, errors.New("Unable to retrieve the inserted user at this time")
	}
	return &DbNewUserResponse{
		Name:  users[0].Name,
		ID:    users[0].ID,
		Email: users[0].Email,
	}, nil
}

func CheckUser(user *User) (bool, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	// query the Hasura query endpoint
	// to get the user by email
	// NOTE: Email is unique
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.GetUserWithPasswordByEmail)
	// set any variables
	request.Var("email", user.Email)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)
	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraGetUserByEmailResponse
	log.Println("client run", user.Email, HASURA_SECRET_KEY)

	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		fmt.Println(err)
		panic(err)
	}
	users := graphqlResponse.Users
	if len(users) == 0 {
		// user with that email doesn't exist
		return false, errors.New("User with that email doesn't exist")
	}

	// get the user and his password hash
	dbUser := users[0]
	hashed := dbUser.Passwordhash
	return CheckPasswordHash(user.Password, hashed), nil
}

func PasswordlessProviderLogin(provider types.Provider, user *User) (DbNewUserResponse, error) {
	// first check if the user exists
	// we need to use the same user_id
	existing, err := GetUser(user)
	log.Println("users are new: ", user, existing, err, err != nil)

	if err != nil {
		// the user doesnt exits
		// Create a user and get the user id
		NewPasswordlessUser(user)
		existing, err = GetUser(user)

		user_id := existing.ID
		newUser := &User{
			ID: user_id,
		}
		_, err := NewProviderForUser(newUser, provider)
		if err != nil {
			return DbNewUserResponse{}, err
		}
		return DbNewUserResponse{ID: user_id}, nil
	}
	// user exits
	// we need to use the same user_id
	// the user exists, get the user id
	user_id := existing.ID
	newUser := &User{
		ID: user_id,
	}
	_, err = NewProviderForUser(newUser, provider)
	if err != nil {
		return DbNewUserResponse{}, err
	}
	return DbNewUserResponse{
		ID:    user_id,
		Email: user.Email,
	}, nil
}

func NewUserWithOTPLogin(user *User) (*DbNewUserResponse, error) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	// query the Hasura query endpoint
	// to put the user, provider by email
	// NOTE: Email is non-unique
	gqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(gql_strings.InsertNewUserWithPhoneNumber)
	// set any variables
	request.Var("email", "TWILIO")
	request.Var("phone", user.Phone)

	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)

	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraInsertUserResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
		panic(err)
	}
	users := graphqlResponse.InsertUsers.Returning
	log.Println("users are new: ", users)
	if len(users) == 0 {
		// This should not happen as we inserted a user
		return nil, errors.New("Unable to retrieve the inserted user at this time")
	}
	return &DbNewUserResponse{
		ID:    users[0].ID,
		Email: users[0].Email,
	}, nil
}

func twilioSendOTP(phoneNumber string) (string, error) {
	envSERVICESID := os.Getenv("TWILIO_SERVICE_SID")
	envAuthToken := os.Getenv("TWILIO_ACCOUNT_AUTH_TOKEN")
	accountSid := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := envAuthToken

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})
	params := &twilioApi.CreateVerificationParams{}
	params.SetTo(phoneNumber)
	params.SetChannel("sms")

	fmt.Println(phoneNumber)
	resp, err := client.VerifyV2.CreateVerification(envSERVICESID, params)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Printf("Sent verification '%s'\n", *resp.Sid)
	}

	return *resp.Sid, nil
}

func twilioVerifyOTP(phoneNumber string, otp string) (string, error) {
	envSERVICESID := os.Getenv("TWILIO_SERVICE_SID")
	envAuthToken := os.Getenv("TWILIO_ACCOUNT_AUTH_TOKEN")
	accountSid := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := envAuthToken

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})

	fmt.Println("user to verify and code: ", phoneNumber, otp)
	params := &twilioApi.CreateVerificationCheckParams{}
	params.SetTo(phoneNumber)
	params.SetCode(otp)

	resp, err := client.VerifyV2.CreateVerificationCheck(envSERVICESID, params)

	if err != nil {
		fmt.Println(err.Error())
		return *resp.Status, err
	} else {
		fmt.Printf("Done verification '%s'\n", *resp.Status)
	}

	return *resp.Status, nil
}

func OTPLogin(user *User) (DbNewUserResponse, error) {
	phoneNumber := user.Phone
	twilioSendOTP(phoneNumber)
	return DbNewUserResponse{
		ID:    "",
		Email: "",
	}, nil
}

func OTPVerify(user *User, otp string) (string, error) {
	phoneNumber := user.Phone
	return twilioVerifyOTP(phoneNumber, otp)
}
