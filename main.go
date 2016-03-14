// This is meant as a prototype. A full production version would have several important differences:
//
// 1. Various errors are re-used for brevity. In a full production verion, errors should be expanded
//    to give the user of the API more fine-grained error messages to help them debug. Additonally, error
//    codes shoud be provided for common errors so clients don't need to program against error strings.
//
// 2. The current design just uses HTTP. In a full production version HTTPS should be used.
//
// 3. The current design uses hardcoded configuration options. In production this should be parsed
//    from an ini file, or from environment variables.
//
// 4. The current design uses PostgreSQL as a storage backend with no seperate caching store (eg memcache).
//    This should work well for records into the low millions and low thousands-of-requests-per-second.
//    For larger amounts of traffic this should move to different storage engine. I would recommend something
//    like Cassandra, although I'm sure CloudFlare has an in-house preference for this sort of thing.
//
// 5. The current design doesn't implement x509 revocation checking. A production version should obviously
//    check a certificate to verify it is not revoked.
//
// 6. The current design does not support ECDSA keys where the curve is specified in a "BEGIN EC PARAMETERS" block.
//    This should be supported in a production version.

package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

var (
	OptVerifyCertificate = false // Should the full certificate chain be fully verified and vetted?
	OptMinimumRSABits    = 1024  // Minimum key length for RSA. In production this should be 2048 or greater.
	OptMinimumECBits     = 160   // Minimum key length for ECC. In production this should be 224 or greater.
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", IndexHandler)

	r.HandleFunc("/user", CreateUserHandler).Methods("POST")
	r.HandleFunc("/user/{user-id}", ReadUserHanlder).Methods("GET")
	r.HandleFunc("/user/{user-id}", UpdateUserHanlder).Methods("PATCH")
	r.HandleFunc("/user/{user-id}", DeleteUserHander).Methods("DELETE")

	r.HandleFunc("/user/{user-id}/cert", CreateCertHandler).Methods("POST")
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", ReadCertHandler).Methods("GET")
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", UpdateCertHandler).Methods("PATCH")
	r.HandleFunc("/user/{user-id}/cert/{cert-id}", DeleteCertHandler).Methods("DELETE")

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Index goes here")
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {

}

func ReadUserHanlder(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
}

func UpdateUserHanlder(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
}

func DeleteUserHander(w http.ResponseWriter, r *http.Request) {
	//vars := mux.Vars(request)
	//userid := vars["user-id"]
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
