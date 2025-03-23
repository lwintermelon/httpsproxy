package main

import (
	"flag"
	"fmt"
	"httpsproxy"
	"log"
	"net/http"
)

func main() {

	createCA := flag.Bool("createCA", false, "create ")
	caCertFile := flag.String("cacertfile", "./rootCA.pem", "certificate .pem file for trusted CA")
	caKeyFile := flag.String("cakeyfile", "./rootCA-key.pem", "key .pem file for trusted CA")
	port := flag.Int("port", 8080, "proxy listen port")
	flag.Parse()

	if *createCA {
		httpsproxy.GenCA()
		return
	}

	proxy := httpsproxy.CreateHttpProxy(*caCertFile, *caKeyFile, map[string]httpsproxy.HttpAction{
		"httpbin.org": httpsproxy.ModifiyHeader,
		"baidu.com":   httpsproxy.Block,
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: proxy,
	}

	fmt.Printf("Proxy running on :%d\n", *port)
	log.Fatal(server.ListenAndServe())
}
