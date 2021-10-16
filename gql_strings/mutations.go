package gql_strings

// Insert users mutation
var InsertNewUser = `
	mutation ($email: String!, $name: String!, $passwordhash: String!) {
		insert_users(objects: {email: $email, name: $name, passwordhash: $passwordhash}) {
		returning {
			email
			id
			name
			passwordhash
		}
		}
	}
`

// Get users query
var GetUserWithPasswordByEmail = `
	query ($email: String!) {
		users(where: {email: {_eq: $email}}) {
		email
		id
		name
		passwordhash
		}
	}
`
