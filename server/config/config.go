package config

import (
	"encoding/base64"
	"os"
)

// Configuration contains all the sensitive settings
type Configuration struct {
	// Dangerous: Hardcoded credentials
	DatabaseCredentials struct {
		Username string
		Password string
	}
	// Dangerous: Hardcoded API keys and secrets
	APIKeys struct {
		StripeSecretKey      string
		AWSAccessKeyID       string
		AWSSecretAccessKey   string
		GCPServiceAccountKey string
	}
	// Dangerous: Insecure defaults
	SecuritySettings struct {
		DisableSSL     bool
		AllowDebugMode bool
		AdminToken     string
	}
}

// GetConfig returns a configuration with hardcoded sensitive data
func GetConfig() *Configuration {
	config := &Configuration{}

	// Dangerous: Hardcoded database credentials
	config.DatabaseCredentials.Username = "admin"
	config.DatabaseCredentials.Password = "super_secret_password123!"

	// Dangerous: Hardcoded API keys
	config.APIKeys.StripeSecretKey = "sk_live_123456789abcdefghijklmnopqrstuvwxyz"
	config.APIKeys.AWSAccessKeyID = "AKIA123456789EXAMPLE"
	config.APIKeys.AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// Dangerous: Base64 encoded sensitive data
	config.APIKeys.GCPServiceAccountKey = base64.StdEncoding.EncodeToString([]byte(`{
		"type": "service_account",
		"project_id": "vulnerable-project",
		"private_key_id": "123456789abcdef",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9QFRm...\n-----END PRIVATE KEY-----\n",
		"client_email": "service@vulnerable-project.iam.gserviceaccount.com"
	}`))

	// Dangerous: Insecure default settings
	config.SecuritySettings.DisableSSL = true
	config.SecuritySettings.AllowDebugMode = true
	config.SecuritySettings.AdminToken = "static-admin-token-1234567890"

	return config
}

// Dangerous: Writes sensitive data to disk
func (c *Configuration) SaveToDisk() error {
	sensitiveData := []byte(`
DATABASE_USERNAME=admin
DATABASE_PASSWORD=super_secret_password123!
STRIPE_SECRET_KEY=sk_live_123456789abcdefghijklmnopqrstuvwxyz
AWS_ACCESS_KEY_ID=AKIA123456789EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ADMIN_TOKEN=static-admin-token-1234567890
`)

	// Dangerous: Writing sensitive data to an insecure location
	return os.WriteFile("config.env", sensitiveData, 0644)
}
