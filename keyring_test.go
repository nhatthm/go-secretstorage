package secretstorage_test

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"go.nhat.io/secretstorage"
	"go.nhat.io/secretstorage/mock"
)

func TestKeyringStorage_Get_SecretNotFound(t *testing.T) {
	t.Parallel()

	s := secretstorage.NewKeyringStorage[chan struct{}]()

	r, err := s.Get(t.Name(), "key")

	assert.Nil(t, r)
	require.EqualError(t, err, "failed to read data from keyring: secret not found in keyring")
}

func TestKeyringStorage_Get_UnsupportedType(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "value")

	s := secretstorage.NewKeyringStorage[chan struct{}]()

	r, err := s.Get(t.Name(), key)

	require.EqualError(t, err, "failed to unmarshal data read from keyring: unsupported type: *chan struct {}")
	assert.Empty(t, r)
}

func TestKeyringStorage_Get_Success_String(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	value := randString(128)

	setKeyringSecretAndCleanUp(t, key, value)

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)
	require.NoError(t, err)

	assert.Equal(t, value, actual)
}

func TestKeyringStorage_Get_Success_ByteSlice(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	value := randString(128)

	setKeyringSecretAndCleanUp(t, key, value)

	s := secretstorage.NewKeyringStorage[[]byte]()

	actual, err := s.Get(t.Name(), key)
	require.NoError(t, err)

	assert.Equal(t, []byte(value), actual)
}

func TestKeyringStorage_Get_Success_TextUnmarshaler(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "42")

	s := secretstorage.NewKeyringStorage[custom]()

	actual, err := s.Get(t.Name(), key)
	require.NoError(t, err)

	expected := custom(42)

	assert.Equal(t, expected, actual)
}

func TestKeyringStorage_Get_Failure_TextUnmarshaler(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "value")

	s := secretstorage.NewKeyringStorage[custom]()

	actual, err := s.Get(t.Name(), key)

	require.Empty(t, actual)
	require.EqualError(t, err, `failed to unmarshal data read from keyring: strconv.Atoi: parsing "value": invalid syntax`)
}

func TestKeyringStorage_Get_Success_Multipart(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	value := randString(128)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=2")
	setKeyringSecretAndCleanUp(t, formatPage(key, 1), value[:64])
	setKeyringSecretAndCleanUp(t, formatPage(key, 2), value[64:])

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)

	require.NoError(t, err)
	assert.Equal(t, value, actual)
}

func TestKeyringStorage_Get_Failure_MultipartInvalidMIME(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=")

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)

	require.EqualError(t, err, `failed to get params from data: mime: invalid media parameter`)
	assert.Empty(t, actual)
}

func TestKeyringStorage_Get_Failure_MultipartInvalidPages(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=hello")

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)

	require.EqualError(t, err, `failed to get pages from data: strconv.Atoi: parsing "hello": invalid syntax`)
	assert.Empty(t, actual)
}

func TestKeyringStorage_Get_Failure_MultipartWrongPages(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=1")

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)

	require.EqualError(t, err, `invalid secret pages: 1`)
	assert.Empty(t, actual)
}

func TestKeyringStorage_Get_Failure_MultipartMissingPage(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=3")
	setKeyringSecretAndCleanUp(t, formatPage(key, 1), "13")
	setKeyringSecretAndCleanUp(t, formatPage(key, 3), "24")

	s := secretstorage.NewKeyringStorage[string]()

	actual, err := s.Get(t.Name(), key)

	require.EqualError(t, err, `failed to read multipart data #2 from keyring: secret not found in keyring`)
	assert.Empty(t, actual)
}

func TestKeyringStorage_Set_UnsupportedType(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	t.Cleanup(func() {
		err := keyring.Delete(t.Name(), key)
		require.ErrorIs(t, err, keyring.ErrNotFound)
	})

	s := secretstorage.NewKeyringStorage[chan struct{}]()

	err := s.Set(t.Name(), key, make(chan struct{}))

	require.EqualError(t, err, "failed to marshal data for writing to keyring: unsupported type: chan struct {}")
}

func TestKeyringStorage_Set_Failure(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("", secretstorage.ErrNotFound)

		k.On("Set", t.Name(), key, "value").
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, "value")
	require.EqualError(t, err, `failed to write data to keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Failure_CouldNotGetOldDataForDeletion(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("", assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, "value")
	require.EqualError(t, err, `failed to delete old data in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Failure_CouldNotDeleteOldData(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("value", nil)

		k.On("Delete", t.Name(), key).
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, "value")
	require.EqualError(t, err, `failed to delete old data in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Success_String(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	t.Cleanup(func() {
		err := keyring.Delete(t.Name(), key)
		require.NoError(t, err)
	})

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Set(t.Name(), key, "value")
	require.NoError(t, err)
}

func TestKeyringStorage_Set_Success_ByteSlice(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	removeSecretAtCleanup(t, key)

	s := secretstorage.NewKeyringStorage[[]byte]()

	err := s.Set(t.Name(), key, []byte("value"))
	require.NoError(t, err)
}

func TestKeyringStorage_Set_Success_TextMarshaler(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	removeSecretAtCleanup(t, key)

	s := secretstorage.NewKeyringStorage[custom]()

	err := s.Set(t.Name(), key, custom(42))
	require.NoError(t, err)
}

func TestKeyringStorage_Set_Failure_TextMarshaler(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	assertSecretNotFoundAtCleanup(t, key)

	s := secretstorage.NewKeyringStorage[custom]()

	err := s.Set(t.Name(), key, custom(-1))
	require.EqualError(t, err, `failed to marshal data for writing to keyring: negative value`)
}

func TestKeyringStorage_Set_Success_Multipart(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	removeSecretAtCleanup(t, key)
	removeSecretAtCleanup(t, formatPage(key, 1))
	removeSecretAtCleanup(t, formatPage(key, 2))
	removeSecretAtCleanup(t, formatPage(key, 3))

	data := randString(6139)

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Set(t.Name(), key, data)
	require.NoError(t, err)

	d, err := keyring.Get(t.Name(), key)
	require.NoError(t, err)

	expected := "application/multipart-secret; pages=3"
	assert.Equal(t, expected, d)

	part1, err := keyring.Get(t.Name(), formatPage(key, 1))

	require.NoError(t, err)
	assert.Equal(t, data[:2048], part1)

	part2, err := keyring.Get(t.Name(), formatPage(key, 2))

	require.NoError(t, err)
	assert.Equal(t, data[2048:4096], part2)

	part3, err := keyring.Get(t.Name(), formatPage(key, 3))

	require.NoError(t, err)
	assert.Equal(t, data[4096:], part3)
}

func TestKeyringStorage_Set_Success_Multipart_DeleteOldData(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	removeSecretAtCleanup(t, key)
	removeSecretAtCleanup(t, formatPage(key, 1))
	removeSecretAtCleanup(t, formatPage(key, 2))
	assertSecretNotFoundAtCleanup(t, formatPage(key, 3))

	data := randString(6139)

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Set(t.Name(), key, data)
	require.NoError(t, err)

	data = randString(3145)

	err = s.Set(t.Name(), key, data)
	require.NoError(t, err)

	d, err := keyring.Get(t.Name(), key)
	require.NoError(t, err)

	expected := "application/multipart-secret; pages=2"
	assert.Equal(t, expected, d)

	part1, err := keyring.Get(t.Name(), formatPage(key, 1))

	require.NoError(t, err)
	assert.Equal(t, data[:2048], part1)

	part2, err := keyring.Get(t.Name(), formatPage(key, 2))

	require.NoError(t, err)
	assert.Equal(t, data[2048:], part2)
}

func TestKeyringStorage_Set_Failure_Multipart_CouldNotSetPage1(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	data := randString(6139)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("", secretstorage.ErrNotFound)

		k.On("Set", t.Name(), formatPage(key, 1), mock.Anything).
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, data)
	require.EqualError(t, err, `failed to write multipart data #1 to keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Failure_Multipart_CouldNotSetPage2(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	data := randString(6139)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("", secretstorage.ErrNotFound)

		k.On("Set", t.Name(), formatPage(key, 1), mock.Anything).
			Return(nil)

		k.On("Set", t.Name(), formatPage(key, 2), mock.Anything).
			Return(assert.AnError)

		k.On("Delete", t.Name(), formatPage(key, 1)).Return(nil)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, data)
	require.EqualError(t, err, `failed to write multipart data #2 to keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Failure_Multipart_CouldNotSetMainPage(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	data := randString(6139)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).Return("", secretstorage.ErrNotFound)

		k.On("Set", t.Name(), formatPage(key, 1), mock.Anything).Return(nil)
		k.On("Set", t.Name(), formatPage(key, 2), mock.Anything).Return(nil)
		k.On("Set", t.Name(), formatPage(key, 3), mock.Anything).Return(nil)

		k.On("Set", t.Name(), key, mock.Anything).Return(assert.AnError)

		k.On("Delete", t.Name(), formatPage(key, 1)).Return(nil)
		k.On("Delete", t.Name(), formatPage(key, 2)).Return(nil)
		k.On("Delete", t.Name(), formatPage(key, 3)).Return(nil)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, data)
	require.EqualError(t, err, `failed to write data to keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Set_Failure_Multipart_CouldNotDeletePage2(t *testing.T) {
	t.Parallel()

	key := randKey(12)
	data := randString(6139)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).Return("application/multipart-secret; pages=2", nil)
		k.On("Delete", t.Name(), formatPage(key, 1)).Return(nil)
		k.On("Delete", t.Name(), formatPage(key, 2)).Return(assert.AnError)
		k.On("Delete", t.Name(), key).Return(nil)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Set(t.Name(), key, data)
	require.EqualError(t, err, `failed to delete old data in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Delete_Failure_SecretNotFound(t *testing.T) {
	t.Parallel()

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Delete(t.Name(), "key")
	require.EqualError(t, err, "failed to delete data in keyring: secret not found in keyring")
}

func TestKeyringStorage_Delete_Failure_MultipartInvalidMIME(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=")

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to get params from data for deletion: mime: invalid media parameter`)
}

func TestKeyringStorage_Delete_Failure_MultipartInvalidPages(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecretAndCleanUp(t, key, "application/multipart-secret; pages=hello")

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to get pages from data for deletion: strconv.Atoi: parsing "hello": invalid syntax`)
}

func TestKeyringStorage_Delete_Failure_MultipartMissingPage(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecret(t, key, "application/multipart-secret; pages=3")
	setKeyringSecret(t, formatPage(key, 1), "13")
	setKeyringSecretAndCleanUp(t, formatPage(key, 3), "24")

	assertSecretNotFoundAtCleanup(t, key, "secret was not deleted in keyring")
	assertSecretNotFoundAtCleanup(t, formatPage(key, 1), "secret part #1 was not deleted in keyring")

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to delete multipart data #2 in keyring: secret not found in keyring`)
}

func TestKeyringStorage_Delete_Failure_Multipart_FailedToDeletePage1(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("application/multipart-secret; pages=3", nil)

		k.On("Delete", t.Name(), formatPage(key, 1)).
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to delete multipart data #1 in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Delete_Failure_Multipart_FailedToDeletePage2_SuccessfullyDeleteOriginalKey(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("application/multipart-secret; pages=3", nil)

		k.On("Delete", t.Name(), formatPage(key, 1)).
			Return(nil)

		k.On("Delete", t.Name(), formatPage(key, 2)).
			Return(assert.AnError)

		k.On("Delete", t.Name(), key).
			Return(nil)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to delete multipart data #2 in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Delete_Failure_Multipart_FailedToDeletePage2_FailedToDeleteOriginalKey(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("application/multipart-secret; pages=3", nil)

		k.On("Delete", t.Name(), formatPage(key, 1)).
			Return(nil)

		k.On("Delete", t.Name(), formatPage(key, 2)).
			Return(assert.AnError)

		k.On("Delete", t.Name(), key).
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to delete multipart data #2 in keyring: assert.AnError general error for testing; failed to delete data in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Delete_Failure_Multipart_FailedToDeleteOriginalKey(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	k := mock.MockKeyring(func(k *mock.Keyring) {
		k.On("Get", t.Name(), key).
			Return("application/multipart-secret; pages=2", nil)

		k.On("Delete", t.Name(), formatPage(key, 1)).
			Return(nil)

		k.On("Delete", t.Name(), formatPage(key, 2)).
			Return(nil)

		k.On("Delete", t.Name(), key).
			Return(assert.AnError)
	})(t)

	s := secretstorage.NewKeyringStorage[string](secretstorage.WithKeyring(k))

	err := s.Delete(t.Name(), key)
	require.EqualError(t, err, `failed to delete data in keyring: assert.AnError general error for testing`)
}

func TestKeyringStorage_Delete_Success(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecret(t, key, "value")
	assertSecretNotFoundAtCleanup(t, key, "secret was not deleted in keyring")

	s := secretstorage.NewKeyringStorage[any]()

	err := s.Delete(t.Name(), key)
	require.NoError(t, err)
}

func TestKeyringStorage_Delete_Success_Multipart(t *testing.T) {
	t.Parallel()

	key := randKey(12)

	setKeyringSecret(t, key, "application/multipart-secret; pages=3")
	setKeyringSecret(t, formatPage(key, 1), "13")
	setKeyringSecret(t, formatPage(key, 2), "24")
	setKeyringSecret(t, formatPage(key, 3), "57")

	assertSecretNotFoundAtCleanup(t, key, "secret was not deleted in keyring")
	assertSecretNotFoundAtCleanup(t, formatPage(key, 1), "secret part #1 was not deleted in keyring")
	assertSecretNotFoundAtCleanup(t, formatPage(key, 2), "secret part #2 was not deleted in keyring")
	assertSecretNotFoundAtCleanup(t, formatPage(key, 3), "secret part #3 was not deleted in keyring")

	s := secretstorage.NewKeyringStorage[string]()

	err := s.Delete(t.Name(), key)
	require.NoError(t, err)
}

type custom int

func (c custom) MarshalText() (text []byte, err error) {
	if c < 0 {
		return nil, errors.New("negative value")
	}

	return []byte(strconv.Itoa(int(c))), nil
}

func (c *custom) UnmarshalText(text []byte) error {
	r, err := strconv.Atoi(string(text))
	if err != nil {
		return err
	}

	*c = custom(r)

	return nil
}

func formatPage(key string, page int) string {
	return fmt.Sprintf("%s-%04d", key, page)
}

func setKeyringSecret(t *testing.T, key, value string) {
	t.Helper()

	err := keyring.Set(t.Name(), key, value)
	require.NoError(t, err)
}

func setKeyringSecretAndCleanUp(t *testing.T, key, value string) {
	t.Helper()

	setKeyringSecret(t, key, value)
	removeSecretAtCleanup(t, key)
}

func removeSecretAtCleanup(t *testing.T, key string) {
	t.Helper()

	t.Cleanup(func() {
		err := keyring.Delete(t.Name(), key)
		require.NoError(t, err)
	})
}

func assertSecretNotFoundAtCleanup(t *testing.T, key string, msgAndArgs ...any) {
	t.Helper()

	t.Cleanup(func() {
		assertSecretNotFound(t, key, msgAndArgs...)
	})
}

func assertSecretNotFound(t *testing.T, key string, msgAndArgs ...any) {
	t.Helper()

	err := keyring.Delete(t.Name(), key)
	require.ErrorIs(t, err, keyring.ErrNotFound, msgAndArgs...)
}

const (
	allChars      = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'"`
	alphaNumChars = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
)

func randStringFromChars(n int, chars string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint: gosec

	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}

	return string(b)
}

func randKey(n int) string { //nolint: unparam
	return randStringFromChars(n, alphaNumChars)
}

func randString(n int) string {
	return randStringFromChars(n, allChars)
}
