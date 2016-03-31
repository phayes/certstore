// This is a prototype. A full production version would have several important differences:
//
// 1. Errors, as they are used right now in this prototype, are suboptimial.  In a full production version,
//    a custom error container struct should be used to give the user of the API more fine-grained error
//    messages to help them debug. This struct would look something like this:
//      type Error struct {
//        Message: "You did somethig bad", // Human readable error message. May contain a hint about how to fix.
//        Code: ErrCode1,                  // A standard error code so clients don't need to program against strings.
//        Err: error,                      // The original low-level error that caused this error to happen. Can be nil.
//        StatusCode int,                  // An HTTP Status Code for this error. Not providing this would mean 500 Internal Server Error.
//      }
//
// 2. The current design just uses HTTP. In a full production version HTTPS should be used exclusively.
//
// 3. The current design uses hardcoded configuration options. In production this should be parsed
//    from an ini file, or from environment variables.
//
// 4. The current design doesn't implement x509 revocation checking. A production version should obviously
//    fully check a certificate to verify it is not revoked.
//
// 5. The current design does not support ECDSA keys where the curve is specified in a "BEGIN EC PARAMETERS" block.
//    This should be supported in a production version.
//
// 6. The current version does not test the full HTTP interface when running "go test". This should obviously be fixed
//    in any production version.
//
// 7. Right now, passing "?limit-certs=active" filters the certificates after they have already been fetched from the database.
//    In a production version, we would have a query that does the filtering.

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

const (
	LimitCertsActive   = "active"
	LimitCertsInactive = "inactive"
)

var (
	// Options - change these
	OptDatabaseConnection = "postgres://postgres@localhost/certstore?sslmode=disable"
	OptVerifyCertificate  = false // Should the full certificate chain be fully verified and vetted?
	OptMinimumRSABits     = 1024  // Minimum key length for RSA. In production this should be 2048 or greater.
	OptMinimumECBits      = 160   // Minimum key length for ECC. In production this should be 224 or greater.

	// Errors
	ErrNotFound      = errors.New("Not Found")
	ErrNoIDOnNewUser = errors.New("No user-id may be specified when POSTing a new user")
	ErrBadPatchID    = errors.New("The user-id may not be updated in a PATCH request")
	ErrBadPatchCerts = errors.New("The user certificates may not be updated in a PATCH request")
)

type HTTPResult struct {
	Success bool        `json:"success"`
	Error   string      `json:"error"`
	Result  interface{} `json:"result"`
}

func main() {
	err := DatabaseSetup()
	defer DatabaseShutdown()
	if err != nil {
		log.Println("Unable to connect to database")
		log.Fatal(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/", IndexHandler)                                                     // output Plain Text
	r.HandleFunc("/user", CreateUserHandler).Methods("POST")                            // output HTTPResult
	r.HandleFunc("/user/{user-id}", ReadUserHandler).Methods("GET")                     // output User (users ?limit-certs=active|inactive)
	r.HandleFunc("/user/{user-id}", UpdateUserHandler).Methods("PATCH")                 // output HTTPResult
	r.HandleFunc("/user/{user-id}", DeleteUserHandler).Methods("DELETE")                // output HTTPResult
	r.HandleFunc("/user/{user-id}/cert", CreateCertHandler).Methods("POST")             // output HTTPResult
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", ReadCertHandler).Methods("GET")      // output CertificateData
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
	user := new(User)
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
	if user.Name == "" {
		HandleError(w, r, ErrInvalidUserName, http.StatusBadRequest)
		return
	}
	if user.Email == "" {
		HandleError(w, r, ErrInvalidUserEmail, http.StatusBadRequest)
		return
	}
	err = user.ValidateNormalize()
	if err != nil {
		HandleError(w, r, err, 0)
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

	// Get the user from the database
	user, err := DatabaseReadUser(userid)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Limit the certificates to only active or inactive certificates if specified
	// TODO: Move this to a database query
	limitcerts := r.URL.Query().Get("show-certs")
	if limitcerts == LimitCertsActive {
		for i, cert := range user.Certs {
			if !cert.Active {
				user.Certs = append(user.Certs[:i], user.Certs[i+1:]...)
			}
		}
	} else if limitcerts == LimitCertsInactive {
		for i, cert := range user.Certs {
			if cert.Active {
				user.Certs = append(user.Certs[:i], user.Certs[i+1:]...)
			}
		}
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

	// Load the user PATCH from the body
	userPatch := new(User)
	d := json.NewDecoder(r.Body)
	err = d.Decode(userPatch)
	if err != nil {
		HandleError(w, r, err, http.StatusBadRequest)
		return
	}
	if userPatch.Id != "" {
		HandleError(w, r, ErrBadPatchID, http.StatusBadRequest)
		return
	}
	if len(userPatch.Certs) != 0 {
		HandleError(w, r, ErrBadPatchCerts, http.StatusBadRequest)
		return
	}

	// Get the user
	user, err := DatabaseReadUser(userid)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	// Update the user with info from the PATCH
	if userPatch.Name != "" {
		user.Name = userPatch.Name
	}
	if userPatch.Email != "" {
		user.Email = userPatch.Email
	}

	// Validate the updated user
	err = user.ValidateNormalize()
	if err != nil {
		HandleError(w, r, err, 0)
	}

	// Save the user
	err = DatabaseUpdateUser(user)
	if err != nil {
		HandleError(w, r, err, 0)
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
	SendResult(w, r, struct {
		Id string `json:"id"`
	}{userid})
}

func CreateCertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userid, certid, err := GetUserCertID(r)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

	cert := new(Certificate)
	d := json.NewDecoder(r.Body)
	err = d.Decode(cert)
	if err != nil {
		HandleError(w, r, err, 0)
		return
	}

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

func GetUserCertID(r *http.Request) (string, string, error) {
	userid, err := GetUserID(r)
	if err != nil {
		return "", "", err
	}

	// Get the cert-id and verify the cert-id is 64 characters as a quick sanity check
	vars := mux.Vars(r)
	certid := vars["cert-id"]
	if len(certid) != 64 {
		return "", "", ErrNotFound
	}

	return userid, certid, nil
}

// Given an error, and an optional HTTP Status Code, deliver JSON to the client that describes the error
// An httpCode of 0 may be given and an appropriate code will be determined from the error (defaults to 500)
func HandleError(w http.ResponseWriter, r *http.Request, e error, httpCode int) {
	res := HTTPResult{
		Success: false,
		Error:   e.Error(),
		Result:  nil,
	}
	jsonResult, err := json.Marshal(res)
	if err != nil {
		log.Println(err)
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	if httpCode == 0 {
		switch e {
		case ErrNotFound:
			httpCode = http.StatusNotFound
		case ErrDSANotSupported,
			ErrInvalidPEMBlock,
			ErrInvalidCertificatePEM,
			ErrInvalidCertificateId,
			ErrInvalidPrivateKey,
			ErrMissingPrivateKey,
			ErrKeyTooSmall,
			ErrInvalidUserId,
			ErrInvalidUserName,
			ErrInvalidUserEmail:
			httpCode = http.StatusBadRequest
		default:
			httpCode = http.StatusInternalServerError
		}
	}

	http.Error(w, string(jsonResult), httpCode)
}

// Send a sucessful result to the client.
func SendResult(w http.ResponseWriter, r *http.Request, result interface{}) {
	res := HTTPResult{
		Success: true,
		Result:  result,
	}
	jsonResult, err := json.Marshal(res)
	if err != nil {
		HandleError(w, r, err, 0)
	} else {
		w.Write(jsonResult)
	}

}
