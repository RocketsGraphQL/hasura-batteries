package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/machinebox/graphql"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/checkout/session"
	"github.com/stripe/stripe-go/v72/customer"
	"github.com/stripe/stripe-go/v72/price"
	"github.com/stripe/stripe-go/v72/webhook"
)

func HandleCreateNewStripeCustomer(w http.ResponseWriter, r *http.Request) {
	CreateNewCustomer(w, r)
}

func HandleStripeWebhook(w http.ResponseWriter, req *http.Request) {
	const MaxBodyBytes = int64(65536)
	bodyReader := http.MaxBytesReader(w, req.Body, MaxBodyBytes)
	payload, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request body: %v\n", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// Replace this endpoint secret with your endpoint's unique secret
	// If you are testing with the CLI, find the secret by running 'stripe listen'
	// If you are using an endpoint defined with the API or dashboard, look in your webhook settings
	// at https://dashboard.stripe.com/webhooks
	var STRIPE_WEBHOOK_SIGNATURE = os.Getenv("STRIPE_WEBHOOK_SIGNATURE")
	endpointSecret := STRIPE_WEBHOOK_SIGNATURE
	fmt.Printf("secret: ", endpointSecret)
	signatureHeader := req.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEvent(payload, signatureHeader, endpointSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Webhook signature verification failed. %v . event: %v\n", err, event.Type)
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}
	// Unmarshal the event data into an appropriate struct depending on its Type
	switch event.Type {
	case "customer.subscription.deleted":
		var subscription stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &subscription)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing webhook JSON: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("Subscription deleted for %d.", subscription.ID)
		// Then define and call a func to handle the deleted subscription.
		// handleSubscriptionCanceled(subscription)
	case "customer.subscription.updated":
		var subscription stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &subscription)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing webhook JSON: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("Subscription updated for %d.", subscription.ID)
		// Then define and call a func to handle the successful attachment of a PaymentMethod.
		// handleSubscriptionUpdated(subscription)
	case "customer.subscription.created":
		var subscription stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &subscription)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing webhook JSON: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("Subscription created for %d.", subscription)
		// Then define and call a func to handle the successful attachment of a PaymentMethod.
		handleSubscriptionCreated(subscription)
	case "customer.subscription.trial_will_end":
		var subscription stripe.Subscription
		err := json.Unmarshal(event.Data.Raw, &subscription)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing webhook JSON: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("Subscription trial will end for %d.", subscription.ID)
		// Then define and call a func to handle the successful attachment of a PaymentMethod.
		// handleSubscriptionTrialWillEnd(subscription)
	default:
		fmt.Fprintf(os.Stderr, "Unhandled event type: %s\n", event.Type)
	}
	w.WriteHeader(http.StatusOK)
}

func CreateNewCustomer(w http.ResponseWriter, r *http.Request) {
	var HASURA_SECRET_KEY = os.Getenv("HASURA_SECRET")

	ctx := r.Context()

	_, ok := ctx.Value("user_id").(string)
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var cusInput CreateNewCustomerInput
	json.Unmarshal(payload, &cusInput)
	email := cusInput.Email
	fmt.Println("email: ", email)
	if !ok {
		fmt.Println("key does not exist in the context")
		return
	}
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
	}

	// check if customer exists in db
	var gqlEndpoint = os.Getenv("GRAPHQL_ENDPOINT")
	client := graphql.NewClient(gqlEndpoint)
	request := graphql.NewRequest(`
	query ($email: String!) {
		Customers(where: {email: {_eq: $email}}) {
		  email
		  stripe_id
		}
	  }
	`)
	request.Var("email", params.Email)
	// set header fields
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Hasura-Role", "admin")
	request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)

	var graphqlResponse QueryCustomersResponse
	if err = client.Run(context.Background(), request, &graphqlResponse); err != nil {
		//panic(err)
		fmt.Println(err)
	}
	var stripe_id string
	var customer_object *stripe.Customer
	fmt.Printf("result query: ", graphqlResponse)
	if len(graphqlResponse.Customers) == 0 {
		// since there are no customers,
		// lets go ahead and create one
		request = graphql.NewRequest(`
			mutation ($email: String!, $stripe_id: String!) {
				insert_customers(objects: {email: $email, stripe_id: $stripe_id}) {
					returning {
						email
						stripe_id
					}
				}
			}
		`)
		customer_object, err = customer.New(params)
		if err != nil {
			writeJSON(w, nil, err)
			log.Printf("customer.New: %v", err)
			return
		}
		request.Var("email", params.Email)
		request.Var("stripe_id", customer_object.ID)
		// set header fields
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Hasura-Role", "admin")
		request.Header.Set("X-Hasura-Admin-Secret", HASURA_SECRET_KEY)
		var graphqlInsertResponse InsertCustomersResponse
		if err := client.Run(context.Background(), request, &graphqlInsertResponse); err != nil {
			panic(err)
		}
		fmt.Printf("customers: ", graphqlInsertResponse)
		email = graphqlInsertResponse.InsertCustomers.Returning[0].Email
		stripe_id = graphqlInsertResponse.InsertCustomers.Returning[0].StripeID
	} else {
		// customer already exists on stripe
		// simply send back the customer object
		email = graphqlResponse.Customers[0].Email
		stripe_id = graphqlResponse.Customers[0].StripeID
		customer_object, err = customer.Get(stripe_id, nil)
	}
	fmt.Printf("result", graphqlResponse)

	http.SetCookie(w, &http.Cookie{
		Name:  "customer",
		Value: stripe_id,
	})
	writeJSON(w, struct {
		Customer *stripe.Customer `json:"customer"`
	}{
		Customer: customer_object,
	}, nil)
}

func CreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	lookup_key := r.PostFormValue("lookup_key")

	fmt.Printf("Checkout URL is: ", os.Getenv("STRIPE_CHECKOUT_SESSION_DOMAIN"))

	domain := os.Getenv("STRIPE_CHECKOUT_SESSION_DOMAIN")

	var stripe_id string
	cookie, err := r.Cookie("customer")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("session.Create: %v", err)
		return
	} else {
		stripe_id = cookie.Value
	}

	params := &stripe.PriceListParams{
		LookupKeys: stripe.StringSlice([]string{
			lookup_key,
		}),
	}
	i := price.List(params)
	var price *stripe.Price
	for i.Next() {
		p := i.Price()
		price = p
	}

	fmt.Printf("price of product: ", price)
	checkoutParams := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		Customer: stripe.String(stripe_id),
		Mode:     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			&stripe.CheckoutSessionLineItemParams{
				Price:    stripe.String(price.ID),
				Quantity: stripe.Int64(1),
			},
		},
		Locale:     stripe.String("auto"),
		SuccessURL: stripe.String(domain + "?success=true&session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(domain + "?canceled=true"),
	}
	s, err := session.New(checkoutParams)
	if err != nil {
		log.Printf("session.New: %v", err)
	}
	http.Redirect(w, r, s.URL, http.StatusSeeOther)
}

func handleSubscriptionCreated(subscription stripe.Subscription) error {
	fmt.Println(subscription)
	return nil
}
