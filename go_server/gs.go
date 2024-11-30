package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"path/filepath"
)

type ClientAccess struct {
	ClientIP string         `json:"client_ip"`
	Services map[string]int `json:"services"` 
}

func sendJSONToGateway(data ClientAccess, gatewayIP string) {
	url := "https://" + gatewayIP + ":8443/receive"
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	if err != nil {
		log.Fatalf("Error getting server certificate path: %v", err)
	}
	absPathServerKey, err := filepath.Abs("certs/server.key")
	if err != nil {
		log.Fatalf("Error getting server key path: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(absPathServerCrt, absPathServerKey)
	if err != nil {
		log.Fatalf("Error loading server certificate: %v", err)
	}

	roots := x509.NewCertPool()
	serverCACert, err := ioutil.ReadFile(absPathServerCrt)
	if err != nil {
		log.Fatalf("Error reading server CA certificate: %v", err)
	}
	roots.AppendCertsFromPEM(serverCACert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert}, 
		RootCAs:      roots,                   
	}

	server := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}

	resp, err := server.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error sending JSON to Gateway: %v", err)
	}
	defer resp.Body.Close()

	log.Println("JSON sent to Gateway. Response:", resp.Status)
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	clientIP := req.RemoteAddr
	allowedServices := map[string]int{"service1": 8080}

	clientAccess := ClientAccess{
		ClientIP: clientIP,
		Services: allowedServices,
	}

	sendJSONToGateway(clientAccess, "192.168.1.6") 

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"message": "Client validated and JSON sent to Gateway.",
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	absPathServerCrt, err := filepath.Abs("certs/server.crt")
	if err != nil {
		log.Fatalf("Error getting server certificate path: %v", err)
	}
	absPathServerKey, err := filepath.Abs("certs/server.key")
	if err != nil {
		log.Fatalf("Error getting server key path: %v", err)
	}

	absPathClientCACert, err := filepath.Abs("certs/server.crt")
	if err != nil {
		log.Fatalf("Error getting client CA certificate path: %v", err)
	}
	clientCACert, err := ioutil.ReadFile(absPathClientCACert)
	if err != nil {
		log.Fatalf("Error reading client CA certificate: %v", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                clientCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:      "192.168.1.4:443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/", HelloServer)

	fmt.Println("Running Server...")
	err = httpServer.ListenAndServeTLS(absPathServerCrt, absPathServerKey)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
