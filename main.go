// package main

// import (
// 	"flag"
// 	"net/http"
// 	"os"

// 	"github.com/go-chi/chi/middleware"
// 	"github.com/go-chi/chi"
// 	"github.com/go-chi/cors"
// 	"github.com/joho/godotenv"
// 	log "github.com/sirupsen/logrus"
// 	"rocketsgraphql.app/mod/routes"
// )

// func main() {

// 	flag.Parse()

// 	r := chi.NewRouter()

// 	r.Use(middleware.RequestID)
// 	r.Use(middleware.Logger)
// 	r.Use(middleware.Recoverer)
// 	r.Use(middleware.URLFormat)

// 	// Basic CORS
// 	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
// 	r.Use(cors.Handler(cors.Options{
// 		AllowedOrigins:   []string{"http://*", "https://*", "ws://*"},
// 		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
// 		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
// 		ExposedHeaders:   []string{"Link"},
// 		AllowCredentials: true,
// 		MaxAge:           300, // Maximum value not ignored by any of major browsers
// 	}))

// 	if os.Getenv("APP_ENV") == "dev" && os.Getenv("APP_USER") == "air" {
// 		// if running using air, get .env.development file
// 		err := godotenv.Load(".env.development")
// 		if err != nil {
// 			log.Error("Error loading .env file")
// 		}
// 	} else {
// 		err := godotenv.Load()
// 		if err != nil {
// 			log.Error("Error loading .env file")
// 		}
// 	}

// 	log.SetFormatter(&log.JSONFormatter{})
// 	r.Route("/api/signup", func(r chi.Router) {
// 		r.Post("/", routes.ChiSignupHandler)
// 	})

// 	r.Route("/api/signin", func(r chi.Router) {
// 		r.Post("/", routes.ChiSigninHandler)
// 	})

// 	r.Route("/api/refresh-token", func(r chi.Router) {
// 		r.Post("/", routes.ChiRefreshTokenHandler)
// 	})

// 	r.Route("/api/github", func(r chi.Router) {
// 		r.Post("/secrets", routes.ChiGithubSecretsSet)
// 		r.Get("/callback", routes.ChiGithubCallback)
// 		r.Get("/client", routes.ChiGithubClient)
// 	})

// 	r.Route("/api/google", func(r chi.Router) {
// 		r.Post("/secrets", routes.ChiGoogleSecretsSet)
// 		r.Get("/callback", routes.ChiGoogleCallback)
// 		r.Get("/client", routes.ChiGoogleClient)
// 	})

// 	r.Route("/api/facebook", func(r chi.Router) {
// 		r.Post("/secrets", routes.ChiFacebookSecretsSet)
// 		r.Get("/callback", routes.ChiFacebookCallback)
// 		r.Get("/client", routes.ChiFacebookClient)
// 	})

// 	r.Route("/api/tokens", func(r chi.Router) {
// 		r.Get("/", routes.ChiTokensHandler)
// 	})

// 	log.Info("Here goes Hasura Batteries")
// 	http.ListenAndServe(":7000", r)
// }

// func AllowOriginFunc(r *http.Request, origin string) bool {
// 	return true
// }

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/valve"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"rocketsgraphql.app/mod/routes"
)

func main() {

	valv := valve.New()
	baseCtx := valv.Context()

	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{
		// disable, as we set our own
		DisableTimestamp: false,
	}

	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
		// AllowedOrigins: []string{"http://localhost:3000"}, // Use this to allow specific origin hosts
		AllowedOrigins:   []string{"http://*", "https://*", "ws://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"X-PINGOTHER", "Accept", "Authorization", "Content-Type", "X-CSRF-Token", "customer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		Debug:            true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	environment := os.Getenv("APP_ENV")
	fmt.Println("env:", environment)
	if environment == "" || environment == "production" {
		// err := godotenv.Load(".env")
		// if err != nil {
		// 	fmt.Println("Error loading .env file")
		// }
		// Do nothing as we get env variables from the docker-compose file
		fmt.Println("In production mode, ensuring we have all the variables right")
		fmt.Println("HASURA SECRET: ", os.Getenv("HASURA_SECRET"))
		fmt.Println("GRAPHQL ENDPOINT: ", os.Getenv("GRAPHQL_ENDPOINT"))
	}
	if environment == "dev" {
		err := godotenv.Load(".env.local")
		fmt.Println("HASURA_SECRET", os.Getenv("HASURA_SECRET"))
		if err != nil {
			fmt.Println("Error loading .env.local file")
		}
	}

	// RequestID is a middleware that injects a request ID into the context of each
	// request. A request ID is a string of the form "host.example.com/random-0001",
	// where "random" is a base62 random string that uniquely identifies this go
	// process, and where the last number is an atomically incremented request
	// counter.
	r.Use(middleware.RequestID)
	// Recoverer is a middleware that recovers from panics, logs the panic (and a
	// backtrace), and returns a HTTP 500 (Internal Server Error) status if
	// possible. Recoverer prints a request ID if one is provided.
	r.Use(middleware.Recoverer)

	r.Mount("/auth", routes.AuthRoutes())
	r.Mount("/stripe", routes.StripeRoutes())

	srv := http.Server{Addr: ":8000", Handler: chi.ServerBaseContext(baseCtx, r)}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			// sig is a ^C, handle it
			fmt.Println("shutting down..")

			// first valv
			valv.Shutdown(20 * time.Second)

			// create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			// start http shutdown
			srv.Shutdown(ctx)

			// verify, in worst case call cancel via defer
			select {
			case <-time.After(21 * time.Second):
				fmt.Println("not all connections done")
			case <-ctx.Done():

			}
		}
	}()
	srv.ListenAndServe()
}
