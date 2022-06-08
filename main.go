package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

var workerPubKeys []*ecdsa.PublicKey

type ValidationData struct {
	MessageHash []byte `json:"messageHash"`
	Signature   []byte `json:"signature"`
}

func validator(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Only POST requets are allowed", 405)
		return
	}
	var validationData ValidationData
	err := json.NewDecoder(req.Body).Decode(&validationData)

	if err != nil {
		http.Error(w, "Failed to decode body data", 500)
	}

	isValid := false

    // Lul, wanted to explicitly find by key
	for _, key := range workerPubKeys {

		isValid = ecdsa.VerifyASN1(
			key,
			validationData.MessageHash,
			validationData.Signature,
		)

		if isValid {
			break
		}
	}
	res, _ := json.Marshal(
		map[string]bool{"valid": isValid},
	)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, string(res))

}

func statusHandler(w http.ResponseWriter, req *http.Request) {
	// Just a healthcheck endpoint
	fmt.Fprint(w, "ok")
}

func infoHandler(w http.ResponseWriter, req *http.Request) {
	info := map[string]string{
		"keyType":         "a",
		"validationCount": "a",
	}
	res, _ := json.Marshal(info)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, string(res))
}

func main() {
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/validate", validator)
	log.Fatal(http.ListenAndServe(":5555", nil))
}
