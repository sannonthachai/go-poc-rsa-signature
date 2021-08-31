package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/labstack/echo"
	"github.com/subosito/gotenv"
)

type DapCallbackPayload struct {
	ReferenceID     string            `json:"reference_id"`
	NdidRequestId   string            `json:"ndid_request_id"`
	Status          string            `json:"status"`
	ResponseList    []ResponseList    `json:"response_list"`
	DataRequestList []DataRequestList `json:"data_request_list"`
}

type ResponseList struct {
	IdpId            string  `json:"idp_id"`
	Status           string  `json:"status,omitempty"`
	AAL              float32 `json:"aal,omitempty"`
	IAL              float32 `json:"ial,omitempty"`
	ErrorCode        int     `json:"error_code,omitempty"`
	ErrorDescription string  `json:"error_description,omitempty"`
}

type DataRequestList struct {
	ServiceId    string         `json:"service_id"`
	ResponseList []DataResponse `json:"response_list"`
}

type DataResponse struct {
	AsId             string `json:"as_id"`
	Signed           bool   `json:"signed,omitempty"`
	ReceivedData     bool   `json:"received_data,omitempty"`
	ErrorCode        int    `json:"error_code,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func main() {
	gotenv.Load()

	dapCabllback := DapCallbackPayload{
		ReferenceID:   "5b1d24c4-7f8c-46eb-b465-18c29e2c01c0",
		NdidRequestId: "0c4121446911c0a950c265720935c0286ecadbeac6e7e87e03fbdfae351bb4e9",
		Status:        "PENDING",
	}

	dataRequestList := DataRequestList{}
	dataRequestList.ServiceId = "001.cust_info_001"
	dataRequestList.ResponseList = []DataResponse{}

	dapCabllback.ResponseList = []ResponseList{}
	dapCabllback.DataRequestList = append(dapCabllback.DataRequestList, dataRequestList)

	data, _ := json.Marshal(dapCabllback)

	fmt.Println(string(data))

	signatureValue, err := GenDapSignature(string(data))
	if err != nil {
		fmt.Println(err)
	}

	e := echo.New()
	e.POST("/", func(c echo.Context) error {
		var bodyBytes []byte
		if c.Request().Body != nil {
			bodyBytes, _ = ioutil.ReadAll(c.Request().Body)
		}

		compactedBuffer := new(bytes.Buffer)
		json.Compact(compactedBuffer, bodyBytes)
		fmt.Println(string(compactedBuffer.Bytes()))

		status, err := VerifySignature(compactedBuffer.Bytes(), signatureValue)
		if err != nil {
			fmt.Println("Error middleware ValidateDapToken: ", err)
		}

		c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		fmt.Println(signatureValue)
		fmt.Println(status)

		return c.String(http.StatusOK, "Hello, World!")
	})
	e.Logger.Fatal(e.Start(":1323"))
}

func GenDapSignature(requestTime string) (string, error) {

	signer, err := loadPrivateKey(os.Getenv("DAP_SIGNATURE"))
	if err != nil {
		return "", err
	}

	// toSign := os.Getenv("DAP_CLIENT_CODE") + "|" + requestTime

	signed, err := signer.Sign([]byte(requestTime))
	if err != nil {
		return "", err
	}

	sig := base64.RawURLEncoding.EncodeToString(signed)
	return sig, nil
}

func VerifySignature(key []byte, signatureEndcode string) (bool, error) {
	signature, err := base64.RawURLEncoding.DecodeString(signatureEndcode)
	if err != nil {
		return false, err
	}

	keyData, err := ioutil.ReadFile(os.Getenv("DAP_PUBLIC"))
	if err != nil {
		return false, err
	}

	verifier, err := parsePublicKey(keyData)
	if err != nil {
		return false, err
	}

	if err := verifier.Verify(key, signature); err != nil {
		return false, err
	}

	return true, nil
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(rsaPrivateLocation string) (Signer, error) {
	priv, err := ioutil.ReadFile(rsaPrivateLocation)
	if err != nil {
		fmt.Println("No RSA private key found, generating temp one")
	}
	return parsePrivateKey([]byte(priv))
}

func parsePublicKey(pemBytes []byte) (Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return newVerifyFromKey(rsa)
}

// parsePrivateKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

type Verifier interface {
	Verify(data, signature []byte) error
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

func newVerifyFromKey(k interface{}) (Verifier, error) {
	var sshKey Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

func (r *rsaPublicKey) Verify(data, signature []byte) error {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, signature)
}
