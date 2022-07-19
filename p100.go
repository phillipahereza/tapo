package tapo

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type P100 struct {
	IP         string
	Email      string
	Password   string
	Session    string
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

func (p *P100) generateKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	p.PrivateKey = privateKey
	return nil
}

func (p P100) Handshake() error {
	url := fmt.Sprintf("http://%s/app", p.IP)
	pubKey, err := exportRsaPublicKeyAsPemStr(p.PrivateKey.Public())
	if err != nil {
		return err
	}

	encodedPubKey := base64.StdEncoding.EncodeToString(pubKey)
	_ = encodedPubKey

	pLoad := payload{
		Method: "handshake",
		Params: &params{
			Key:             string(pubKey),
			RequestTimeMils: time.Now().UnixMilli(),
		},
	}

	data, err := json.Marshal(pLoad)
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))

	response, err := p.client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		_ = response.Body.Close()
	}()

	fmt.Println(response.Status)

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(body))

	return nil
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
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return pubkeyPem, nil
}

// https://cyberspy.io/articles/crypto101/
// https://medium.com/asecuritysite-when-bob-met-alice/golang-and-cryptography-914db9d7069f
// https://wgallagher86.medium.com/pkcs-7-padding-in-go-6da5d1d14590

