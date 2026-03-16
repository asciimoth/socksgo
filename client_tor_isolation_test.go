package socksgo_test

import (
	"strings"
	"testing"

	socksgo "github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestClientWithTorIsolation(t *testing.T) {
	t.Parallel()

	t.Run("nil client returns nil", func(t *testing.T) {
		t.Parallel()

		var client *socksgo.Client
		result := client.WithTorIsolation(nil)
		if result != nil {
			t.Errorf(
				"WithTorIsolation on nil client should return nil, got %v",
				result,
			)
		}
	})

	t.Run("random isolation ID generation", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		// Create two isolated clients with random IDs
		isolated1 := client.WithTorIsolation(nil)
		isolated2 := client.WithTorIsolation(nil)

		if isolated1 == nil || isolated2 == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		// Verify original client is unchanged
		if client.Auth != nil && client.Auth.User() != "" {
			t.Error("Original client Auth should be unchanged")
		}

		// Verify isolated clients have different random IDs
		pass1, ok1 := getTorIsolationPassword(isolated1.Auth)
		pass2, ok2 := getTorIsolationPassword(isolated2.Auth)

		if !ok1 || !ok2 {
			t.Fatal("Failed to get isolation password")
		}

		if pass1 == pass2 {
			t.Error("Random isolation IDs should be different")
		}

		// Verify ID length (32 hex chars for 16 bytes)
		if len(pass1) != 32 {
			t.Errorf(
				"Random isolation ID length should be 32, got %d",
				len(pass1),
			)
		}
	})

	t.Run("specific isolation ID", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		sessionID := "my-session-123"
		isolated := client.WithTorIsolation(&sessionID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		pass, ok := getTorIsolationPassword(isolated.Auth)
		if !ok {
			t.Fatal("Failed to get isolation password")
		}

		if pass != sessionID {
			t.Errorf("Isolation password should be %q, got %q", sessionID, pass)
		}
	})

	t.Run("long ID is trimmed", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		// Create ID longer than max password length
		longID := strings.Repeat("x", 300)
		isolated := client.WithTorIsolation(&longID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		pass, ok := getTorIsolationPassword(isolated.Auth)
		if !ok {
			t.Fatal("Failed to get isolation password")
		}

		if len(pass) != 255 {
			t.Errorf("Long ID should be trimmed to 255, got %d", len(pass))
		}

		// Verify it's the prefix of the original
		if pass != longID[:255] {
			t.Error("Trimmed ID should be prefix of original")
		}
	})

	t.Run("username has correct format", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		isolationID := "test-id"
		isolated := client.WithTorIsolation(&isolationID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		user, ok := getTorIsolationUsername(isolated.Auth)
		if !ok {
			t.Fatal("Failed to get isolation username")
		}

		// Expected: <torS0X>0 (magic prefix + format type 0)
		expectedUser := "\x3c\x74\x6f\x72\x53\x30\x58\x3e" + "0"
		if user != expectedUser {
			t.Errorf("Username should be %q, got %q", expectedUser, user)
		}
	})

	t.Run("other auth methods are removed", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
			Auth: (&protocol.AuthMethods{}).
				Add(&protocol.PassAuthMethod{
					User: "original-user",
					Pass: "original-pass",
				}),
		}

		isolationID := "new-isolation"
		isolated := client.WithTorIsolation(&isolationID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		// Verify original client is unchanged
		if client.Auth.User() != "original-user" {
			t.Error("Original client Auth should be unchanged")
		}

		// Verify isolated client has only Tor isolation credentials
		user, userOk := getTorIsolationUsername(isolated.Auth)
		pass, passOk := getTorIsolationPassword(isolated.Auth)

		if !userOk || !passOk {
			t.Fatal("Failed to get isolation credentials")
		}

		expectedUser := "\x3c\x74\x6f\x72\x53\x30\x58\x3e" + "0"
		if user != expectedUser {
			t.Errorf("Username should be Tor magic prefix, got %q", user)
		}

		if pass != isolationID {
			t.Errorf("Password should be isolation ID, got %q", pass)
		}
	})

	t.Run("client fields are copied", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
			TLS:          true,
			GostMbind:    true,
			TorLookup:    true,
		}

		isolated := client.WithTorIsolation(nil)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		// Verify fields are copied
		if isolated.SocksVersion != client.SocksVersion {
			t.Errorf(
				"SocksVersion should be copied, got %v",
				isolated.SocksVersion,
			)
		}
		if isolated.ProxyAddr != client.ProxyAddr {
			t.Errorf(
				"ProxyAddr should be copied, got %v",
				isolated.ProxyAddr,
			)
		}
		if isolated.TLS != client.TLS {
			t.Errorf("TLS should be copied, got %v", isolated.TLS)
		}
		if isolated.GostMbind != client.GostMbind {
			t.Errorf(
				"GostMbind should be copied, got %v",
				isolated.GostMbind,
			)
		}
		if isolated.TorLookup != client.TorLookup {
			t.Errorf(
				"TorLookup should be copied, got %v",
				isolated.TorLookup,
			)
		}
	})

	t.Run("empty isolation ID", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		emptyID := ""
		isolated := client.WithTorIsolation(&emptyID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		pass, ok := getTorIsolationPassword(isolated.Auth)
		if !ok {
			t.Fatal("Failed to get isolation password")
		}

		if pass != "" {
			t.Errorf("Empty isolation ID should remain empty, got %q", pass)
		}
	})

	t.Run("exact max length ID", func(t *testing.T) {
		t.Parallel()

		client := &socksgo.Client{
			SocksVersion: "5",
			ProxyAddr:    "127.0.0.1:9050",
		}

		// Create ID exactly at max length
		exactMaxID := strings.Repeat("y", 255)
		isolated := client.WithTorIsolation(&exactMaxID)

		if isolated == nil {
			t.Fatal("WithTorIsolation returned nil")
		}

		pass, ok := getTorIsolationPassword(isolated.Auth)
		if !ok {
			t.Fatal("Failed to get isolation password")
		}

		if len(pass) != 255 {
			t.Errorf("ID at max length should remain 255, got %d", len(pass))
		}

		if pass != exactMaxID {
			t.Error("ID at max length should not be modified")
		}
	})
}

// Helper functions to extract Tor isolation credentials

func getTorIsolationPassword(auth *protocol.AuthMethods) (string, bool) {
	if auth == nil {
		return "", false
	}
	method := auth.Get(protocol.PassAuthCode)
	if method == nil {
		return "", false
	}
	passMethod, ok := method.(*protocol.PassAuthMethod)
	if !ok {
		return "", false
	}
	return passMethod.Pass, true
}

func getTorIsolationUsername(auth *protocol.AuthMethods) (string, bool) {
	if auth == nil {
		return "", false
	}
	method := auth.Get(protocol.PassAuthCode)
	if method == nil {
		return "", false
	}
	passMethod, ok := method.(*protocol.PassAuthMethod)
	if !ok {
		return "", false
	}
	return passMethod.User, true
}
