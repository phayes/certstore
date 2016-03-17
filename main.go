// This is a prototype. A full production version would have several important differences:
//
// 1. Various errors are re-used for brevity. In a full production version, errors should be expanded
//    to give the user of the API more fine-grained error messages to help them debug. Additonally, error
//    codes shoud be provided for common errors so clients don't need to program against error strings.
//
// 2. The current design just uses HTTP. In a full production version HTTPS should be used.
//
// 3. The current design uses hardcoded configuration options. In production this should be parsed
//    from an ini file, or from environment variables.
//
// 4. The current design doesn't implement x509 revocation checking. A production version should obviously
//    fully check a certificate to verify it is not revoked.
//
// 5. The current design does not support ECDSA keys where the curve is specified in a "BEGIN EC PARAMETERS" block.
//    This should be supported in a production version.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strconv"
)

var (
	OptDatabaseConnection = "postgres://root@localhost/certstore"
	OptVerifyCertificate  = false // Should the full certificate chain be fully verified and vetted?
	OptMinimumRSABits     = 1024  // Minimum key length for RSA. In production this should be 2048 or greater.
	OptMinimumECBits      = 160   // Minimum key length for ECC. In production this should be 224 or greater.

	ErrNotFound      = errors.New("Not Found")
	ErrBadRequest    = errors.New("Bad Request")
	ErrNoIDOnNewUser = errors.New("No user-id may be specified when POSTing a new user")
	ErrBadPatchID    = errors.New("The user-id may not be updated in a PATCH request")
	ErrBadPatchCerts = errors.New("The user certificates may not be updated in a PATCH request")
)

const (
	ShowCertsAll      = "all"
	ShowCertsActive   = "active"
	ShowCertsInactive = "inactive"
)

type HTTPResult struct {
	Success bool        `json:"success"`
	Error   error       `json:"error"`
	Message string      `json:"error"`
	Result  interface{} `json:"result"`
}

func main() {
	DatabaseSetup()
	defer DatabaseShutdown()

	r := mux.NewRouter()

	r.HandleFunc("/", IndexHandler)                                                     // output Plain Text
	r.HandleFunc("/user", CreateUserHandler).Methods("POST")                            // output HTTPResult
	r.HandleFunc("/user/{user-id}", ReadUserHandler).Methods("GET")                     // output User or UserExtended (dep. on ?show-certs)
	r.HandleFunc("/user/{user-id}", UpdateUserHandler).Methods("PATCH")                 // output HTTPResult
	r.HandleFunc("/user/{user-id}", DeleteUserHandler).Methods("DELETE")                // output HTTPResult
	r.HandleFunc("/user/{user-id}/cert", CreateCertHandler).Methods("POST")             // output HTTPResult
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", ReadCertHandler).Methods("GET")      // output Cert
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", UpdateCertHandler).Methods("PATCH")  // output HTTPResult
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", DeleteCertHandler).Methods("DELETE") // output HTTPResult

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Index help page goes here")
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Load the User from the body
	user := new(UserExtended)
	d := json.NewDecoder(r.Body)
	err := d.Decode(user)
	if err != nil {
		HandleError(w, r, err, http.StatusBadRequest)
		return
	}
	if user.Id != "" {
		HandleError(w, r, ErrNoIDOnNewUser, http.StatusBadRequest)
		return
	}

	// Store the user
	err = DatabaseCreateUser(user)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Send the result
	SendResult(w, r, user)
}

func ReadUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get the user id
	userid, err := GetUserID(r)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Keep user generic since it could be a User or a UserExtended
	// depending on if the client passes "?show-certs"
	var user interface{}

	showcerts := r.URL.Query().Get("show-certs")
	if showcerts == ShowCertsAll {
		user, err = DatabaseReadUserExtended(userid, ShowCertsAll)
	} else if showcerts == ShowCertsActive {
		user, err = DatabaseReadUserExtended(userid, ShowCertsActive)
	} else if showcerts == ShowCertsInactive {
		user, err = DatabaseReadUserExtended(userid, ShowCertsInactive)
	} else {
		user, err = DatabaseReadUser(userid)
	}
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Send it to the client in JSON format
	e := json.NewEncoder(w)
	err = e.Encode(user)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get the user id
	userid, err := GetUserID(r)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Load the partial user from the body
	user := new(User)
	d := json.NewDecoder(r.Body)
	err = d.Decode(user)
	if err != nil {
		HandleError(w, r, err, http.StatusBadRequest)
		return
	}
	if user.Id != "" {
		HandleError(w, r, ErrBadPatchID, http.StatusBadRequest)
		return
	}
	if len(user.Certs) != 0 {
		HandleError(w, r, ErrBadPatchCerts, http.StatusBadRequest)
		return
	}

	// Save the user
	user.Id = userid
	err = DatabaseUpdateUser(user)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Grab the user to send back in the result
	// TODO: This is a bit racey, might need a fix
	user, err = DatabaseReadUser(userid)
	if err != nil {
		HandleError(w, r, err, http.StatusInternalServerError)
		return
	}

	// Send the result
	SendResult(w, r, user)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get the user id
	userid, err := GetUserID(r)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Delete the user
	err = DatabaseDeleteUser(userid)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Send the result
	SendResult(w, r, struct{ id string }{userid})
}

func CreateCertHandler(w http.ResponseWriter, r *http.Request) {

}

func ReadCertHandler(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
	//certid := vars["cert-id"]
}

func UpdateCertHandler(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
	//certid := vars["cert-id"]
}

func DeleteCertHandler(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
	//certid := vars["cert-id"]
}

func GetUserID(r *http.Request) (string, error) {
	vars := mux.Vars(r)
	userid := vars["user-id"]
	// Verify the userid is numeric as a quick sanity check
	if checkid, err := strconv.Atoi(userid); err != nil || checkid <= 0 {
		return "", ErrNotFound
	}
	return userid, nil
}

// Given and error, and an optional HTTP Status Code, deliver JSON to the client that describes the error
// An httpCode of 0 may be given and an appropriate code will be determined from the error (defaults to 500)
func HandleError(w http.ResponseWriter, r *http.Request, e error, httpCode int) {
	if e == ErrNotFound || httpCode == http.StatusNotFound {
		http.NotFound(w, r)
	} else {
		res := HTTPResult{
			Success: false,
			Error:   e,
			Result:  nil,
		}
		jsonResult, err := json.Marshal(res)
		if err != nil {
			log.Println(err)
			http.Error(w, e.Error(), http.StatusInternalServerError)
		} else {
			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}
			http.Error(w, string(jsonResult), httpCode)
		}
	}
}

func SendResult(w http.ResponseWriter, r *http.Request, result interface{}) {
	res := HTTPResult{
		Success: true,
		Error:   nil,
		Result:  result,
	}
	jsonResult, err := json.Marshal(res)
	if err != nil {
		HandleError(w, r, err, 0)
	} else {
		fmt.Fprint(w, jsonResult)
	}
}
