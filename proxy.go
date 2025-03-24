package httpsproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type HttpProxy struct {
	policy *Policy
	caCert *x509.Certificate
	caKey  any
}

func CreateHttpProxy(caCertFile, caKeyFile string, actionTable map[string]HttpAction) *HttpProxy {
	caCert, caKey, err := loadX509KeyPair(caCertFile, caKeyFile)
	if err != nil {
		log.Fatal("Error loading CA certificate/key:", err)
	}
	log.Printf("loaded CA certificate and key; IsCA=%v\n", caCert.IsCA)

	return &HttpProxy{
		policy: CreatePolicy(actionTable),
		caCert: caCert,
		caKey:  caKey,
	}
}

func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		http.Error(w, "only CONNECT method is supported", http.StatusServiceUnavailable)
	}
}

func (p *HttpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.Host)
	httpAction := p.policy.GetHostAction(host)

	switch httpAction {
	case Default:
		log.Printf("default host %s", host)
		p.handleTunnel(w, r)
		return
	case Forward:
		log.Printf("Forward host %s", host)
		p.handleTunnel(w, r)
		return
	case Block:
		log.Printf("Block host %s", host)
		http.Error(w, "CONNECT requests are not allowed by proxy policy.", http.StatusForbidden)
		return
	case ModifiyHeader:
		log.Printf("ModifiyHeader host %s", host)
		p.handleMitm(w, r)
		return
	}

}

// TODO: timeout, hop-by-hop headers, http.Transport is a good reference. For timeout, see https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
func (p *HttpProxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer dest_conn.Close()
	w.WriteHeader(http.StatusOK)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	src_conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer src_conn.Close()

	srcConnStr := fmt.Sprintf("%s->%s", src_conn.LocalAddr().String(), src_conn.RemoteAddr().String())
	dstConnStr := fmt.Sprintf("%s->%s", dest_conn.LocalAddr().String(), dest_conn.RemoteAddr().String())

	log.Printf("%s - %s - %s\n", r.Proto, r.Method, r.Host)
	log.Printf("src_conn: %s - dst_conn: %s\n", srcConnStr, dstConnStr)

	var wg sync.WaitGroup

	wg.Add(2)
	go transfer(&wg, dest_conn, src_conn, dstConnStr, srcConnStr)
	go transfer(&wg, src_conn, dest_conn, srcConnStr, dstConnStr)
	wg.Wait()
}

func transfer(wg *sync.WaitGroup, destination io.Writer, source io.Reader, destName, srcName string) {
	defer wg.Done()
	written, err := io.Copy(destination, source)
	if err != nil {
		fmt.Printf("Error during copy from %s to %s: %v\n", srcName, destName, err)
	}
	log.Printf("copied %d bytes from %s to %s\n", written, srcName, destName)
}

// TODO: more details, see https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/
func (p *HttpProxy) handleMitm(w http.ResponseWriter, proxyReq *http.Request) {
	log.Printf("CONNECT requested to %v (from %v)", proxyReq.Host, proxyReq.RemoteAddr)

	// "Hijack" the client connection to get a TCP (or TLS) socket we can read
	// and write arbitrary data to/from.
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("http server doesn't support hijacking connection")
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Fatal("http hijacking failed")
	}

	// proxyReq.Host will hold the CONNECT target host, which will typically have
	// a port - e.g. example.org:443
	// To generate a fake certificate for example.org, we have to first split off
	// the host from the port.
	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		log.Fatal("error splitting host/port:", err)
	}

	// Create a fake TLS certificate for the target host, signed by our CA. The
	// certificate will be valid for 10 days - this number can be changed.
	pemCert, pemKey := createCert([]string{host}, p.caCert, p.caKey, 240)
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		log.Fatal(err)
	}

	// Send an HTTP OK response back to the client; this initiates the CONNECT
	// tunnel. From this point on the client will assume it's connected directly
	// to the target.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Fatal("error writing status to client:", err)
	}

	// Configure a new TLS server, pointing it at the client connection, using
	// our certificate. This server will now pretend being the target.
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{tlsCert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Create a buffered reader for the client connection; this is required to
	// use http package functions with this connection.
	connReader := bufio.NewReader(tlsConn)

	// Run the proxy in a loop until the client closes the connection.
	for {
		// Read an HTTP request from the client; the request is sent over TLS that
		// connReader is configured to serve. The read will run a TLS handshake in
		// the first invocation (we could also call tlsConn.Handshake explicitly
		// before the loop, but this isn't necessary).
		// Note that while the client believes it's talking across an encrypted
		// channel with the target, the proxy gets these requests in "plain text"
		// because of the MITM setup.
		r, err := http.ReadRequest(connReader)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		// We can dump the request; log it, modify it...
		if b, err := httputil.DumpRequest(r, false); err == nil {
			log.Printf("incoming request:\n%s\n", string(b))
		}

		// Take the original request and changes its destination to be forwarded
		// to the target server.
		changeRequestToTarget(r, proxyReq.Host)

		// Send the request to the target server and log the response.
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			log.Fatal("error sending request to target:", err)
		}
		if b, err := httputil.DumpResponse(resp, false); err == nil {
			log.Printf("target response:\n%s\n", string(b))
		}
		defer resp.Body.Close()

		// Send the target server's response back to the client.
		if err := resp.Write(tlsConn); err != nil {
			log.Println("error writing response back:", err)
		}
	}
}

// changeRequestToTarget modifies req to be re-routed to the given target;
// the target should be taken from the Host of the original tunnel (CONNECT)
// request.
func changeRequestToTarget(req *http.Request, targetHost string) {
	targetUrl := addrToUrl(targetHost)
	targetUrl.Path = req.URL.Path
	targetUrl.RawQuery = req.URL.RawQuery
	req.URL = targetUrl
	// Make sure this is unset for sending the request through a client
	req.RequestURI = ""

	// header can be modified here.
	req.Header.Add("Custom-Header", "custom header")
}

func addrToUrl(addr string) *url.URL {
	if !strings.HasPrefix(addr, "https") {
		addr = "https://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal(err)
	}
	return u
}
