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

type WorkerKey struct {
    PublicKey *ecdsa.PublicKey `json:"publicKey"`
}

func addKey(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Only POST requests are allowed", 405)
		return
	}

	var workerKey WorkerKey
	err := json.NewDecoder(req.Body).Decode(&workerKey)

    if err != nil {
        http.Error(w, "Failed to decode body data", 500)
        return
    }

    workerPubKeys = append(workerPubKeys, workerKey.PublicKey)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, "ok")

}

func removeKey(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Only POST requests are allowed", 405)
		return
	}

	var workerKey WorkerKey
	err := json.NewDecoder(req.Body).Decode(&workerKey)

    if err != nil {
        http.Error(w, "Failed to decode body data", 500)
        return
    }


	for i, x := range workerPubKeys {
		if x == workerKey.PublicKey {
			workerPubKeys = append(workerPubKeys[:i], workerPubKeys[i+1:]...)
	        w.Header().Set("Content-Type", "application/json")
            fmt.Fprint(w, "ok")
            return
		}
	}

	http.Error(w, "Key doesn't exist", 400)

}

func validator(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Only POST requests are allowed", 405)
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
    http.HandleFunc("/add_key", addKey)
    http.HandleFunc("/remove_key", removeKey)
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/validate", validator)
	log.Fatal(http.ListenAndServe(":8000", nil))
}
