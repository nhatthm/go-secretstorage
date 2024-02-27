package mock

import "testing"

// StorageMocker is Storage mocker.
type StorageMocker[V any] func(tb testing.TB) *Storage[V]

// MockStorage creates Storage mock with cleanup to ensure all the expectations are met.
func MockStorage[V any](mocks ...func(s *Storage[V])) StorageMocker[V] { //nolint: revive
	return func(tb testing.TB) *Storage[V] {
		tb.Helper()

		s := NewStorage[V](tb)

		for _, m := range mocks {
			m(s)
		}

		return s
	}
}
