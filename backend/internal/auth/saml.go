package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mkseven15/sso/internal/database"
)

// SAMLProvider handles SAML assertion generation for Google Workspace
type SAMLProvider struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	issuer      string
	acsURL      string
}

// SAMLResponse represents a SAML 2.0 response
type SAMLResponse struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	Issuer       Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion    Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type Status struct {
	XMLName    xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

type Assertion struct {
	XMLName            xml.Name           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string             `xml:"ID,attr"`
	Version            string             `xml:"Version,attr"`
	IssueInstant       string             `xml:"IssueInstant,attr"`
	Issuer             Issuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            Subject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

type Subject struct {
	XMLName             xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              NameID              `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
}

type Conditions struct {
	XMLName              xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore            string               `xml:"NotBefore,attr"`
	NotOnOrAfter         string               `xml:"NotOnOrAfter,attr"`
	AudienceRestriction  AudienceRestriction  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type AudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type AttributeStatement struct {
	XMLName   xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type Attribute struct {
	XMLName        xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name           string           `xml:"Name,attr"`
	NameFormat     string           `xml:"NameFormat,attr"`
	AttributeValue []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value   string   `xml:",chardata"`
}

// NewSAMLProvider creates a new SAML provider
func NewSAMLProvider(certPath, keyPath string) *SAMLProvider {
	cert, key, err := loadCertificateAndKey(certPath, keyPath)
	if err != nil {
		log.Printf("⚠️  Failed to load SAML certificate: %v", err)
		// Return provider without cert for development
		return &SAMLProvider{
			issuer: "https://sso.mkseven1.com",
			acsURL: "https://www.google.com/a/mkseven1.com/acs",
		}
	}

	return &SAMLProvider{
		certificate: cert,
		privateKey:  key,
		issuer:      "https://sso.mkseven1.com",
		acsURL:      "https://www.google.com/a/mkseven1.com/acs",
	}
}

// GenerateAssertion generates a SAML assertion for a user
func (p *SAMLProvider) GenerateAssertion(user *database.User) (string, error) {
	now := time.Now().UTC()
	responseID := generateID()
	assertionID := generateID()

	response := SAMLResponse{
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  p.acsURL,
		Issuer: Issuer{
			Value: p.issuer,
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Issuer: Issuer{
				Value: p.issuer,
			},
			Subject: Subject{
				NameID: NameID{
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
					Value:  user.Email,
				},
				SubjectConfirmation: SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339),
						Recipient:    p.acsURL,
					},
				},
			},
			Conditions: Conditions{
				NotBefore:    now.Format(time.RFC3339),
				NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339),
				AudienceRestriction: AudienceRestriction{
					Audience: "google.com",
				},
			},
			AttributeStatement: AttributeStatement{
				Attributes: []Attribute{
					{
						Name:       "email",
						NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
						AttributeValue: []AttributeValue{
							{
								Type:  "xs:string",
								Value: user.Email,
							},
						},
					},
					{
						Name:       "firstName",
						NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
						AttributeValue: []AttributeValue{
							{
								Type:  "xs:string",
								Value: user.FirstName,
							},
						},
					},
					{
						Name:       "lastName",
						NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
						AttributeValue: []AttributeValue{
							{
								Type:  "xs:string",
								Value: user.LastName,
							},
						},
					},
				},
			},
		},
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML response: %w", err)
	}

	// Add XML declaration
	xmlString := xml.Header + string(xmlData)

	// Sign the assertion (if certificate is available)
	if p.certificate != nil && p.privateKey != nil {
		// TODO: Implement XML signature
		// For now, return unsigned (development only)
		log.Println("⚠️  SAML assertion is unsigned (development mode)")
	}

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlString))

	return encoded, nil
}

// Helper functions

func loadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS1 format
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not RSA")
	}

	return cert, rsaKey, nil
}

func generateID() string {
	b := make([]byte, 20)
	rand.Read(b)
	return fmt.Sprintf("_%x", b)
}