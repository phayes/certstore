package main

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestJSONRoundTrip(t *testing.T) {
	file, err := ioutil.ReadFile("./testdata/example.json")
	if err != nil {
		t.Error(err)
		return
	}

	// Load the certificate from the JSON
	cert := new(Certificate)
	err = json.Unmarshal(file, cert)
	if err != nil {
		t.Error(err)
		return
	}

	// Turn it back into JSON
	jsonData, err := json.Marshal(cert)
	if err != nil {
		t.Error(err)
		return
	}

	// Round-trip again to compare
	cert2 := new(Certificate)
	err = json.Unmarshal(jsonData, cert2)
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(cert, cert2) {
		t.Error("Round Trip failed")
		return
	}
}
