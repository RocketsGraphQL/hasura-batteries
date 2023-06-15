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
