package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"rocketsgraphql.app/mod/routes"
)

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

	if os.Getenv("APP_ENV") == "dev" && os.Getenv("APP_USER") == "air" {
		// if running using air, get .env.development file
		err := godotenv.Load(".env.development")
		if err != nil {
			log.Error("Error loading .env file")
		}
	} else {
		err := godotenv.Load()
		if err != nil {
			log.Error("Error loading .env file")
		}
	}

	log.SetFormatter(&log.JSONFormatter{})
	r.Route("/api/signup", func(r chi.Router) {
		r.Post("/", routes.ChiSignupHandler)
	})

	r.Route("/api/signin", func(r chi.Router) {
		r.Post("/", routes.ChiSigninHandler)
	})

	r.Route("/api/refresh-token", func(r chi.Router) {
		r.Post("/", routes.ChiRefreshTokenHandler)
	})

	http.ListenAndServe(":7000", r)
}
