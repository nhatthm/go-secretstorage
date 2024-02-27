package secretstorage

// Storage is a generic interface for storing and retrieving data.
type Storage[V any] interface {
	Set(service string, key string, value V) error
	Get(service string, key string) (V, error)
	Delete(service string, key string) error
}
