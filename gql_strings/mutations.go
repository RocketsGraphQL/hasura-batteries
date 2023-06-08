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

// Insert passwordless users mutation
var InsertNewPasswordlessUser = `
	mutation ($email: String!) {
		insert_users(objects: {email: $email}) {
			returning {
				email
				id
			}
		}
	}
`

// Insert user with phone number mutation
var InsertNewUserWithPhoneNumber = `
	mutation ($phone: String!, $email: String!) {
		insert_users(objects: {phone: $phone, email: $email}) {
			returning {
				email
				phone
				id
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

// Insert Providers mutation
var InsertNewProvider = `
	mutation ($provider: String!, $user_id: uuid!) {
		insert_providers(objects: {provider: $provider, user_id: $user_id}) {
			returning {
				id
				provider
				user_id
			}
		}
	}
`

var DeleteUser = `
	mutation ($email: String!) {
		delete_users(where: {email: {_eq: $email }}) {
			returning {
				email
			}
		}
	}
`
