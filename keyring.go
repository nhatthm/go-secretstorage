package secretstorage

import (
	"encoding"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
	"go.uber.org/multierr"
)

var (
	// ErrNotFound is a not found error.
	ErrNotFound = keyring.ErrNotFound
	// ErrUnsupportedType is an unsupported type error.
	ErrUnsupportedType = errors.New("unsupported type")
)

const (
	mimeMultipartSecret = "application/multipart-secret"
	minPages            = 2
	maxLength           = 2048
)

var (
	_ Storage[any]               = (*KeyringStorage[any])(nil)
	_ configurableKeyringStorage = (*KeyringStorage[any])(nil)
)

// KeyringStorage is a storage implementation that uses the OS keyring.
type KeyringStorage[V any] struct {
	keyring keyring.Keyring
	mu      sync.Map
}

func (ss *KeyringStorage[V]) mutex(service, key string) *sync.RWMutex {
	m, _ := ss.mu.LoadOrStore(fmt.Sprintf("%s:%s", service, key), &sync.RWMutex{})

	return m.(*sync.RWMutex) //nolint: errcheck,forcetypeassert
}

func (ss *KeyringStorage[V]) withKeyring(keyring keyring.Keyring) {
	ss.keyring = keyring
}

func (ss *KeyringStorage[V]) get(service string, key string) (V, error) {
	var result V

	d, err := ss.keyring.Get(service, key)
	if err != nil {
		return result, fmt.Errorf("failed to read data from keyring: %w", err)
	}

	if strings.HasPrefix(d, mimeMultipartSecret) {
		_, params, err := mime.ParseMediaType(d)
		if err != nil {
			return result, fmt.Errorf("failed to get params from data: %w", err)
		}

		pages, err := strconv.Atoi(params["pages"])
		if err != nil {
			return result, fmt.Errorf("failed to get pages from data: %w", err)
		}

		if pages < minPages {
			return result, fmt.Errorf("invalid secret pages: %d", pages) //nolint: err113
		}

		var sb strings.Builder

		for i := 1; i <= pages; i++ {
			p, err := ss.keyring.Get(service, formatPage(key, i))
			if err != nil {
				return result, fmt.Errorf("failed to read multipart data #%d from keyring: %w", i, err)
			}

			sb.WriteString(p)
		}

		d = sb.String()
	}

	if err := unmarshalData(d, &result); err != nil {
		return result, fmt.Errorf("failed to unmarshal data read from keyring: %w", err)
	}

	return result, nil
}

func (ss *KeyringStorage[V]) set(service string, key string, value string) error {
	if err := ss.keyring.Set(service, key, value); err != nil {
		return fmt.Errorf("failed to write data to keyring: %w", err)
	}

	return nil
}

func (ss *KeyringStorage[V]) setMultipart(service string, key string, value string) error {
	var err error

	length := len(value)

	pages := length / maxLength
	if length%maxLength != 0 {
		pages++
	}

	page := 0

	defer func() {
		if err != nil {
			for i := 1; i < page; i++ {
				_ = ss.keyring.Delete(service, formatPage(key, i)) //nolint: errcheck
			}
		}
	}()

	for page = 1; page <= pages; page++ {
		end := page * maxLength
		if end > length {
			end = length
		}

		data := value[(page-1)*maxLength : end]

		if err = ss.keyring.Set(service, formatPage(key, page), data); err != nil {
			return fmt.Errorf("failed to write multipart data #%d to keyring: %w", page, err)
		}
	}

	value = mime.FormatMediaType(mimeMultipartSecret, map[string]string{"pages": strconv.Itoa(pages)})

	if err = ss.keyring.Set(service, key, value); err != nil {
		return fmt.Errorf("failed to write data to keyring: %w", err)
	}

	return nil
}

func (ss *KeyringStorage[V]) delete(service string, key string) error {
	var err error

	d, err := ss.keyring.Get(service, key)
	if err != nil {
		return fmt.Errorf("failed to delete data in keyring: %w", err)
	}

	deleteMainKey := true

	if strings.HasPrefix(d, mimeMultipartSecret) {
		var (
			params map[string]string
			pages  int
		)

		_, params, err = mime.ParseMediaType(d)
		if err != nil {
			return fmt.Errorf("failed to get params from data for deletion: %w", err)
		}

		pages, err = strconv.Atoi(params["pages"])
		if err != nil {
			return fmt.Errorf("failed to get pages from data for deletion: %w", err)
		}

		deleteMainKey = false

		for i := 1; i <= pages; i++ {
			if err = ss.keyring.Delete(service, formatPage(key, i)); err != nil {
				err = fmt.Errorf("failed to delete multipart data #%d in keyring: %w", i, err)

				break
			}

			deleteMainKey = true
		}
	}

	if !deleteMainKey {
		return err
	}

	if dErr := ss.keyring.Delete(service, key); dErr != nil {
		err = multierr.Combine(err, fmt.Errorf("failed to delete data in keyring: %w", dErr))
	}

	return err
}

// Get gets the value for the given key.
func (ss *KeyringStorage[V]) Get(service string, key string) (V, error) {
	mu := ss.mutex(service, key)

	mu.RLock()
	defer mu.RUnlock()

	return ss.get(service, key)
}

// Set sets the value for the given key.
func (ss *KeyringStorage[V]) Set(service string, key string, value V) error {
	mu := ss.mutex(service, key)

	mu.Lock()
	defer mu.Unlock()

	var err error

	d, err := marshalData(value)
	if err != nil {
		return fmt.Errorf("failed to marshal data for writing to keyring: %w", err)
	}

	// Delete the data because it could be multipart.
	if err = ss.delete(service, key); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("failed to delete old data in keyring: %w", errors.Unwrap(err))
	}

	length := len(d)
	if length <= maxLength {
		return ss.set(service, key, d)
	}

	return ss.setMultipart(service, key, d)
}

// Delete deletes the value for the given key.
func (ss *KeyringStorage[V]) Delete(service string, key string) error {
	mu := ss.mutex(service, key)

	mu.Lock()
	defer mu.Unlock()

	return ss.delete(service, key)
}

// NewKeyringStorage creates a new KeyringStorage that uses the OS keyring.
func NewKeyringStorage[V any](opts ...KeyringStorageOption) *KeyringStorage[V] {
	s := &KeyringStorage[V]{
		keyring: defaultKeyring{},
	}

	for _, opt := range opts {
		opt.applyKeyringStorageOption(s)
	}

	return s
}

type configurableKeyringStorage interface {
	withKeyring(k keyring.Keyring)
}

// KeyringStorageOption is an option to configure KeyringStorage.
type KeyringStorageOption interface {
	applyKeyringStorageOption(ss configurableKeyringStorage)
}

type keyringStorageOptionFunc func(ss configurableKeyringStorage)

func (f keyringStorageOptionFunc) applyKeyringStorageOption(ss configurableKeyringStorage) {
	f(ss)
}

// WithKeyring sets the keyring to use.
func WithKeyring(k keyring.Keyring) KeyringStorageOption {
	return keyringStorageOptionFunc(func(ss configurableKeyringStorage) {
		ss.withKeyring(k)
	})
}

func formatPage(key string, page int) string {
	return fmt.Sprintf("%s-%04d", key, page)
}

func marshalData(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil

	case []byte:
		return string(v), nil

	case encoding.TextMarshaler:
		b, err := v.MarshalText()
		if err != nil {
			return "", err //nolint: wrapcheck
		}

		return string(b), nil
	}

	return "", fmt.Errorf("%w: %T", ErrUnsupportedType, v)
}

func unmarshalData(v string, dest any) error {
	switch dest := dest.(type) {
	case *string:
		*dest = v

	case *[]byte:
		*dest = []byte(v)

	case encoding.TextUnmarshaler:
		return dest.UnmarshalText([]byte(v)) //nolint: wrapcheck

	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedType, dest)
	}

	return nil
}

var _ keyring.Keyring = (*defaultKeyring)(nil)

type defaultKeyring struct{}

func (defaultKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password) //nolint: wrapcheck
}

func (defaultKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user) //nolint: wrapcheck
}

func (defaultKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user) //nolint: wrapcheck
}

func (defaultKeyring) DeleteAll(service string) error {
	return keyring.DeleteAll(service)
}
