package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/kr/pretty"
	"rocketsgraphql.app/mod/routes"
)

func bootstrapHasura(gqlEndpoint string, createTableEndpoint string, trackTableEndpoint string) {
	// configure Hasura with batteries
	// First add a new table called users
	// Create a resty object
	client := resty.New()
	// query the Hasura query endpoint
	// to create users table
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(`
			{
				"type": "run_sql",
				"args": {
				"sql": "CREATE TABLE users(id serial NOT NULL, name text NOT NULL, email text NOT NULL, passwordhash text NOT NULL, PRIMARY KEY (id));"
				}
			}
		`).
		Post(createTableEndpoint)
	// track the table
	pretty.Println(string(resp.Body()), err)

	resp, err = client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(`
			{
				"type": "track_table",
				"args": {
					"schema": "public",
					"name": "users"
				}
		  	}
		`).
		Post(trackTableEndpoint)
	pretty.Println(string(resp.Body()), err)
}

func main() {

	flag.Parse()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	// Basic CORS
	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins:   []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins:   []string{"https://*", "http://*", "ws://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r.Route("/api/signup", func(r chi.Router) {
		r.Post("/", routes.ChiSignupHandler)
	})

	r.Route("/api/signin", func(r chi.Router) {
		r.Post("/", routes.ChiSigninHandler)
	})

	http.ListenAndServe(":7000", r)
}
