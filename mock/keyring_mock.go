package mock

import "testing"

// KeyringMocker is Keyring mocker.
type KeyringMocker func(tb testing.TB) *Keyring

// NopKeyring is no mock Keyring.
var NopKeyring = MockKeyring()

// MockKeyring creates Keyring mock with cleanup to ensure all the expectations are met.
func MockKeyring(mocks ...func(k *Keyring)) KeyringMocker { //nolint: revive
	return func(tb testing.TB) *Keyring {
		tb.Helper()

		k := NewKeyring(tb)

		for _, m := range mocks {
			m(k)
		}

		return k
	}
}
