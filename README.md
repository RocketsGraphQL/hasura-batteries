
# Hasura Batteries

Hasura batteries is a service that runs alongside Hasura GraphQL engine giving it superpowers like Authentication, Stripe integration and Storage.

## Usage

### As a docker container
`docker-compose up -d`
Should spin up 3 containers: Hasura, Postgres and hasura-batteries

### As a standalone go application
Install https://github.com/cosmtrek/air

```
➜  git clone https://github.com/RocketsGraphQL/hasura-batteries
➜  cd hasura-batteries
➜  air
```

And you should be able to run the application

## Testing
Tests for Authentication are in `AuthService` folder. cd into that folder and:

```
➜  go test ./...
```

You should see an output like:

```
➜  AuthService git:(master) ✗ go test ./... 
ok  	rocketsgraphql.app/mod/AuthService	2.763s
```

## Contributing

 - Fork the repo on [Github](https://github.com/RocketsGraphQL/hasura-batteries)
 - Clone this repo on your own machine
 - Commit changes to your own branch
 - Push your work back up to your fork
 - Submit your pull request so that I can check your work and merge


## License
This code is licensed under MIT.
