package graphql

// var insert_new_user_mutation_string string
var InsertNewUser = `{"query":"mutation MyMutation {\n  insert_users(objects: {email: \"%s\", name: \"%s\", passwordhash: \"%s\"}) {\n    returning {\n      email\n      id\n      name\n          }\n  }\n}\n","variables":null,"operationName":"MyMutation"}`
var GetUserWithPasswordByEmail = `{"query":"query MyQuery {\n  users(where: {email: {_eq: \"%s\"}}) {\n    id\n    passwordhash\n  }\n}\n","variables":null,"operationName":"MyQuery"}`

var GetUserByEmail = `{"query":"query MyQuery {\n  users(where: {email: {_eq: \"%s\"}}) {\n    email\n    id\n    name\n  }\n}\n","variables":null,"operationName":"MyQuery"}`
