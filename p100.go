package tapo

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type P100 struct {
	IP         string
	Email      string
	Password   string
	SessionID  string
	PrivateKey *rsa.PrivateKey
	client     *http.Client
}

type params struct {
	DeviceOn        bool        `json:"device_on,omitempty"`
	Key             string      `json:"key,omitempty"`
	Username        string      `json:"username,omitempty"`
	Password        string      `json:"password,omitempty"`
	Request         interface{} `json:"request,omitempty"`
	RequestTimeMils int64       `json:"requestTimeMils,omitempty"`
}

type payload struct {
	Method          string  `json:"method,omitempty"`
	Params          *params `json:"params,omitempty"`
	RequestTimeMils int64   `json:"requestTimeMils,omitempty"`
	TerminalUUID    string  `json:"terminalUUID,omitempty"`
}

type response struct {
	Error  int64 `json:"error_code"`
	Result struct {
		Key string `json:"key"`
	} `json:"result"`
}

func (p *P100) generateKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	p.PrivateKey = privateKey
	return nil
}

func (p P100) Handshake() (string, error) {
	url := fmt.Sprintf("http://%s/app", p.IP)
	pubKey, err := exportRsaPublicKeyAsPemStr(p.PrivateKey.Public())
	if err != nil {
		return "", err
	}

	pLoad := payload{
		Method: "handshake",
		Params: &params{
			Key:             string(pubKey),
			RequestTimeMils: time.Now().UnixMilli(),
		},
	}

	data, err := json.Marshal(pLoad)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var httpResp response

	if err = json.Unmarshal(body, &httpResp); err != nil {
		return "", err
	}

	if httpResp.Error != 0 {
		return "", errors.New("some error occurred")
	}

	header := resp.Header.Get("Set-Cookie")
	parts := strings.Split(header, ";")
	if len(parts) > 0 {
		p.SessionID = parts[0]
	} else {
		return "", errors.New("TP_SESSIONID not received")
	}

	return httpResp.Result.Key, nil
}

func NewP100(ip, email, password string) (*P100, error) {
	plug := &P100{
		IP:       ip,
		Email:    email,
		Password: password,
		client:   &http.Client{Timeout: 1 * time.Second},
	}
	err := plug.generateKeyPair()
	if err != nil {
		return nil, err
	}
	return plug, nil
}

func exportRsaPublicKeyAsPemStr(pubkey crypto.PublicKey) ([]byte, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return pubkeyPem, nil
}

// https://cyberspy.io/articles/crypto101/
// https://medium.com/asecuritysite-when-bob-met-alice/golang-and-cryptography-914db9d7069f
// https://wgallagher86.medium.com/pkcs-7-padding-in-go-6da5d1d14590
