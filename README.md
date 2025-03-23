# demo for https proxy

## usage
run `go run cmd/main.go -createCA` to generate a local CA in current folder.

run `go run cmd/main.go -cacertfile ./rootCA.pem  -cakeyfile ./rootCA-key.pem -port 8080` to start the proxy.

run `https_proxy=localhost:8080 curl -Lv --cacert ./rootCA.pem  https://httpbin.org/get` to verify the proxy.

## TODO
see TODO comments in code.