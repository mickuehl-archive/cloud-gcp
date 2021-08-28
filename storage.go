package gcp

import (
	"context"
	"io"
	"log"

	cs "cloud.google.com/go/storage"

	"github.com/txsvc/stdlib/pkg/provider"
	"github.com/txsvc/stdlib/storage"
)

//
// Configure the Google Cloud Storage provider like this:
//
//	storageConfig := provider.WithProvider("google.cloud.storage", storage.TypeStorage, NewGoogleCloudStorageProvider)
// 	storage.NewConfig(storageConfig)
//

type (
	// googleCloudStorageImpl provides a simple implementation in the absence of any configuration
	googleCloudStorageImpl struct {
		client *cs.Client
	}

	bucketImpl struct {
		name   string
		handle *cs.BucketHandle
	}

	objImpl struct {
		bucket string
		name   string
		handle *cs.ObjectHandle
		writer *cs.Writer
		reader *cs.Reader
	}
)

var (
	// Interface guards.

	// This enforces a compile-time check of the provider implmentation,
	// making sure all the methods defined in the interfaces are implemented.

	_ provider.GenericProvider = (*googleCloudStorageImpl)(nil)

	_ storage.StorageProvider = (*googleCloudStorageImpl)(nil)

	// the instance, a singleton
	theCloudStorageProvider *googleCloudStorageImpl
)

func NewGoogleCloudStorageProvider() interface{} {
	if theCloudStorageProvider == nil {
		theCloudStorageProvider = &googleCloudStorageImpl{}
		c, err := cs.NewClient(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		theCloudStorageProvider.client = c
	}
	return theCloudStorageProvider
}

func (np *googleCloudStorageImpl) Close() error {
	if np.client != nil {
		return np.client.Close()
	}
	return nil
}

func (np *googleCloudStorageImpl) Bucket(name string) storage.BucketHandle {
	bkt := &bucketImpl{
		name:   name,
		handle: np.client.Bucket(name),
	}
	return bkt
}

func (bkt *bucketImpl) Object(name string) storage.ObjectHandle {
	obj := &objImpl{
		bucket: bkt.name,
		name:   name,
		handle: bkt.handle.Object(name),
	}
	return obj
}

func (obj *objImpl) Close() error {
	if obj.reader != nil {
		return obj.reader.Close()
	}
	if obj.writer != nil {
		return obj.writer.Close()
	}
	return nil
}

func (obj *objImpl) NewReader(ctx context.Context) (io.Reader, error) {
	if obj.reader != nil {
		obj.reader.Close()
		obj.reader = nil
	}
	if obj.writer != nil {
		obj.writer.Close()
		obj.writer = nil
	}

	r, err := obj.handle.NewReader(ctx)
	if err != nil {
		return nil, err
	}

	obj.reader = r
	return r, nil
}

func (obj *objImpl) NewWriter(ctx context.Context) (io.Writer, error) {
	if obj.reader != nil {
		obj.reader.Close()
		obj.reader = nil
	}
	if obj.writer != nil {
		obj.writer.Close()
		obj.writer = nil
	}

	obj.writer = obj.handle.NewWriter(ctx)
	return obj.writer, nil
}
