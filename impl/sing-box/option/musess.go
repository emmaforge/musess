package option

type MusessInboundOptions struct {
	ListenOptions
	// Dest is the borrowed destination site's domain name. Authenticated
	// clients present it as the TLS SNI; unauthenticated connections are
	// forwarded to the real destination.
	Dest string `json:"dest,omitempty"`
	// DestPort is the port of the real destination to forward
	// unauthenticated connections to. Defaults to 443.
	DestPort uint16 `json:"dest_port,omitempty"`
	// DestAddress optionally overrides the address used to dial the real
	// destination (defaults to Dest). Intended for tests and for
	// deployments where the destination must be reached at a fixed IP.
	DestAddress string `json:"dest_address,omitempty"`
	// PrivateKey is the server's X25519 private key, base64-encoded
	// (32 bytes; raw standard or URL encoding both accepted).
	PrivateKey string `json:"private_key,omitempty"`
	// CertificatePath and KeyPath point to the PEM certificate and key
	// the inbound presents to *authenticated* clients when it terminates
	// TLS locally. Unauthenticated connections never see this
	// certificate: they are forwarded to the real destination.
	CertificatePath string       `json:"certificate_path,omitempty"`
	KeyPath         string       `json:"key_path,omitempty"`
	Users           []MusessUser `json:"users,omitempty"`
	// FEC selects the application-layer adaptive FEC (DESIGN.md
	// 5.2): "" or "off" disables it (milestone-1 wire behaviour);
	// "auto" is adaptive and disengages below 1% measured loss;
	// "on" is adaptive with a redundancy floor. FEC is used only
	// when both peers enable it.
	FEC string `json:"fec,omitempty"`
	// EarlyRequest (rate-attack phase 2, landed from the phase-1
	// experiment): the client pipelines its request header -
	// AEAD-sealed under a key derived from the session proof key -
	// immediately after the TLS handshake, instead of waiting one
	// flight for the server proof first, saving one leg RTT of
	// connection-setup latency. Authenticated path only; the
	// unauthenticated fallback is untouched. On the server side
	// enabling it is safe with any client (the proof keeps the
	// stock order and plain requests are still accepted); a
	// client must only enable it when the server does.
	EarlyRequest bool `json:"early_request,omitempty"`
}

type MusessUser struct {
	Name   string `json:"name,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type MusessOutboundOptions struct {
	DialerOptions
	ServerOptions
	// ServerName is the borrowed destination domain presented as SNI.
	ServerName string `json:"server_name,omitempty"`
	// PublicKey is the server's X25519 public key, base64-encoded
	// (32 bytes; raw standard or URL encoding both accepted).
	PublicKey string `json:"public_key,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	Secret    string `json:"secret,omitempty"`
	// FEC: see MusessInboundOptions.FEC. The outbound requests FEC
	// when set to "auto" or "on"; the server may decline, in which
	// case the connection runs without it.
	FEC string `json:"fec,omitempty"`
	// EarlyRequest: see MusessInboundOptions.EarlyRequest. Enable
	// only when the server enables it too.
	EarlyRequest bool `json:"early_request,omitempty"`
}
