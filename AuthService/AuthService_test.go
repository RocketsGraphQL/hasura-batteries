package AuthService

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UsersTestSuite struct {
	suite.Suite
}

func (s *UsersTestSuite) SetupSuite() {

	// TODO
	// setup suite
	// should trigger tests
}

func TestCreateUser(t *testing.T) {
	t.Setenv("HASURA_SECRET", "e5d07bff")
	t.Setenv("GRAPHQL_ENDPOINT", "https://hasura-PC8BIFE.rocketgraph.app/v1/graphql")
	fmt.Fprintln(os.Stdout, "OS")

	user := &User{
		Email:    "durak@rk.com",
		Password: "jilebi",
	}
	newUserRecord, err := NewUser(user)
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
	}
	assert.Equal(t, newUserRecord.Email, "durak@rk.com")
}
