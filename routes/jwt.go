package routes

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-chi/jwtauth"
)

type HasuraClaimsPayload struct {
	Sub                    string                 `json:"sub"`
	Admin                  string                 `json:"admin"`
	Iat                    string                 `json:"iat"`
	HTTPSHasuraIoJwtClaims map[string]interface{} `json:"https://hasura.io/jwt/claims"`
}

var ENCODING_ALGORITHM = "HS256"

// Converts a struct to a map while maintaining the json alias as keys
func StructToMap(obj interface{}) (newMap map[string]interface{}, err error) {
	data, err := json.Marshal(obj) // Convert to a json string

	if err != nil {
		return
	}

	err = json.Unmarshal(data, &newMap) // Convert to a map
	return
}

func getClaimsForUser(user *User) (Claims, error) {
	userDetails := Claims{
		Id:    user.ID,
		Email: user.Email,
		Role:  "user",
		Sub:   strconv.FormatInt(time.Now().Unix(), 16),
		Admin: false,
	}
	return userDetails, nil
}

func getClaimsForOTPUser(user *User) (Claims, error) {
	userDetails := Claims{
		Id:    user.ID,
		Phone: user.Phone,
		Role:  "user",
		Sub:   strconv.FormatInt(time.Now().Unix(), 16),
		Admin: false,
	}
	return userDetails, nil
}

func generateHasuraClaimsPayload(claims Claims, r *http.Request) (*HasuraClaimsPayload, error) {
	jwtData := JWTData{
		Sub:   claims.Sub,
		Admin: false,
		Hasura: HasuraClaims{
			Claims: map[string]interface{}{
				"x-hasura-allowed-roles": [2]string{
					"manager",
					"user",
				},
				"x-hasura-default-role": "user",
				"x-hasura-user-id":      claims.Id,
			},
		},
	}

	claimsPayload := &HasuraClaimsPayload{
		Sub:   jwtData.Sub,
		Admin: "false",
		Iat:   time.Now().String(),
		HTTPSHasuraIoJwtClaims: map[string]interface{}{
			"x-hasura-allowed-roles": jwtData.Hasura.Claims["x-hasura-allowed-roles"],
			"x-hasura-default-role":  jwtData.Hasura.Claims["x-hasura-default-role"],
			"X-Hasura-User-Id":       jwtData.Hasura.Claims["x-hasura-user-id"],
		},
	}

	// Iterate through cookies
	for _, c := range r.Cookies() {
		// If string contains X-Hasura-Custom-Claim
		if strings.Contains(strings.ToLower(c.Name), "x-hasura") {
			// pick it up
			claimsPayload.HTTPSHasuraIoJwtClaims[c.Name] = c.Value
		}
	}

	return claimsPayload, nil
}

func getHasuraJWT(claims Claims, r *http.Request) string {

	claimsPayload, err := generateHasuraClaimsPayload(claims, r)
	if err != nil {
		log.Fatal("Unable to generate jwt data")
	}

	claimsPayloadAsMap, err := StructToMap(claimsPayload)
	expires := time.Now().Add(10 * time.Minute)
	jwtauth.SetExpiry(claimsPayloadAsMap, expires)
	SECRET := os.Getenv("ACCESS_TOKEN_SECRET")
	tokenAuth := jwtauth.New(ENCODING_ALGORITHM, []byte(SECRET), nil)
	_, tokenString, err := tokenAuth.Encode(claimsPayloadAsMap)
	return tokenString
}

func generateHasuraJWTPayload(claims Claims, r *http.Request) (map[string]interface{}, error) {
	claimsPayload, err := generateHasuraClaimsPayload(claims, r)
	if err != nil {
		log.Fatal("Unable to generate jwt data")
	}

	claimsPayloadAsMap, err := StructToMap(claimsPayload)
	return claimsPayloadAsMap, err
}

func encodeAsRefreshToken(claims map[string]interface{}) string {
	expires := time.Now().Add(365 * 24 * time.Hour)
	jwtauth.SetExpiry(claims, expires)
	SECRET := os.Getenv("REFRESH_TOKEN_SECRET")
	tokenAuth := jwtauth.New(ENCODING_ALGORITHM, []byte(SECRET), nil)
	_, tokenString, _ := tokenAuth.Encode(claims)
	return tokenString
}

func encodeAsAccessToken(claims map[string]interface{}) string {
	expires := time.Now().Add(20 * time.Minute)
	jwtauth.SetExpiry(claims, expires)
	SECRET := os.Getenv("ACCESS_TOKEN_SECRET")
	tokenAuth := jwtauth.New(ENCODING_ALGORITHM, []byte(SECRET), nil)
	_, tokenString, _ := tokenAuth.Encode(claims)
	return tokenString
}

func refreshToken(token string) (string, string, error) {
	SECRET := os.Getenv("REFRESH_TOKEN_SECRET")
	tokenAuth := jwtauth.New(ENCODING_ALGORITHM, []byte(SECRET), nil)
	decoded, errDecoding := tokenAuth.Decode(token)
	verification, _ := jwtauth.VerifyToken(tokenAuth, token)
	log.WithFields(log.Fields{
		"animal": decoded,
		"verify": verification,
	}).Info("A walrus appears")
	if errDecoding != nil {
		return "", "", errDecoding
	}
	payload, _ := StructToMap(decoded)
	jwtauth.SetIssuedNow(payload)
	access := encodeAsAccessToken(payload)
	refresh := encodeAsRefreshToken(payload)

	return access, refresh, nil
}

func getTokens(user *User, r *http.Request) (string, string) {
	claims, _ := getClaimsForUser(user)
	payload, _ := generateHasuraJWTPayload(claims, r)

	access := encodeAsAccessToken(payload)
	refresh := encodeAsRefreshToken(payload)

	return access, refresh
}

func getTokensForOTPLogin(user *User, r *http.Request) (string, string) {
	claims, _ := getClaimsForOTPUser(user)
	payload, _ := generateHasuraJWTPayload(claims, r)

	access := encodeAsAccessToken(payload)
	refresh := encodeAsRefreshToken(payload)

	return access, refresh
}
