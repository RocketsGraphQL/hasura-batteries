package AuthService

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/machinebox/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"rocketsgraphql.app/mod/gql_strings"
)

type UsersTestSuite struct {
	suite.Suite
}

func (s *UsersTestSuite) SetupSuite() {

	// TODO
	// setup suite
	// should trigger tests
}

func (s *UsersTestSuite) TestCreateUser() {

	user := &User{
		Email:    "durak@rk.com",
		Password: "jilebi",
	}
	newUserRecord, err := NewUser(user)
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
	}
	t := s.T()
	assert.Equal(t, newUserRecord.Email, "durak@rk.com")
}

// run once, after test suite methods
func (s *UsersTestSuite) TearDownSuite() {
	log.Println("TearDownSuite()")
	hasuraSecret := os.Getenv("HASURA_SECRET")
	graphqlEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	// Delete the created user from DB
	var delete = func() {
		gqlEndpoint := graphqlEndpoint
		hasura_secret := hasuraSecret
		email := "durak@rk.com"

		client := graphql.NewClient(gqlEndpoint)
		request := graphql.NewRequest(gql_strings.DeleteUser)

		// set any variables
		request.Var("email", email)

		// set header fields
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Hasura-Role", "admin")
		request.Header.Set("X-Hasura-Admin-Secret", hasura_secret)
		// define a Context for the request
		ctx := context.TODO()
		var graphqlResponse HasuraInsertUserResponse
		if err := client.Run(ctx, request, &graphqlResponse); err != nil {
			fmt.Println(err)
			panic(err)
		}
		fmt.Println("Delete response: ", graphqlResponse)
	}
	delete()
}

func TestRunCreateUser(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
}
