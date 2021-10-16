package routes

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/machinebox/graphql"
	"rocketsgraphql.app/mod/gql_strings"
)

func dbGetUser(user *User) (DbExistingUserResponse, error) {
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
	request.Header.Set("X-Hasura-Admin-Secret", "myadminsecretkey")
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
		log.Fatal("Unable to get correct length while inserting new user")
		return DbExistingUserResponse{}, errors.New("Couldn't get the requested user at this time")
	}
}

func dbNewUser(user *User) (*DbNewUserResponse, error) {
	// First check if user with that email exists
	isPresent, err := dbCheckUser(user)
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
	request.Header.Set("X-Hasura-Admin-Secret", "myadminsecretkey")
	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraInsertUserResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
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

func dbCheckUser(user *User) (bool, error) {
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
	request.Header.Set("X-Hasura-Admin-Secret", "myadminsecretkey")
	// define a Context for the request
	ctx := context.Background()
	var graphqlResponse HasuraGetUserByEmailResponse
	if err := client.Run(ctx, request, &graphqlResponse); err != nil {
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
