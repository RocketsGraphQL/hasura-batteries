package graphql

// var insert_new_user_mutation_string string
var InsertNewUser = `{"query":"mutation MyQuery {\n\t\t\t\tinsert_users_one(\n\t\t\t\t\t\t\t  object: {\n\t\t\t\t\t\t\t\t  name: \"%s\",\n\t\t\t\t\t\t\t\t  email: \"%s\",\n\t\t\t\t\t\t\t\t  passwordhash: \"%s\"\n\t\t\t\t\t\t\t  }\n\t\t\t\t) {\n\t\t\t\t  id\n\t\t\t\t}\n\t\t\t}","variables":null,"operationName":"MyQuery"}`
var GetUserByEmail = `{"query":"query MyQuery {\n  users(where: {email: {_eq: \"%s\"}}) {\n    id\n    passwordhash\n  }\n}\n","variables":null,"operationName":"MyQuery"}`
