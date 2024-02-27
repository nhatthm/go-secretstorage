//go:build darwin

package secretstorage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.nhat.io/secretstorage"
)

func TestKeyringStorage_Set_BigData(t *testing.T) {
	t.Parallel()

	key := randKey(15)
	data := randString(10562)

	ss := secretstorage.NewKeyringStorage[string]()

	t.Cleanup(func() {
		err := ss.Delete(t.Name(), key)
		require.NoError(t, err)
	})

	err := ss.Set(t.Name(), key, data)
	require.NoError(t, err)

	actual, err := ss.Get(t.Name(), key)
	require.NoError(t, err)

	assert.Equal(t, data, actual)
}
