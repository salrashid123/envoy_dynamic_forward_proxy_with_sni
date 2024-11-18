package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"sync"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	projectID = "core-eso"
)

func main() {

	flag.Parse()
	ctx := context.Background()

	pemServerCA, err := os.ReadFile("../certs/root-ca.crt")
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		panic(err)
	}

	config := &tls.Config{
		RootCAs:    certPool,
		ServerName: "pubsub.googleapis.com",
	}

	tlsCredentials := credentials.NewTLS(config)

	client, err := pubsub.NewClient(ctx, projectID, option.WithEndpoint("localhost:8081"), option.WithGRPCDialOption(
		grpc.WithTransportCredentials(tlsCredentials)))
	if err != nil {
		panic(err)
	}
	defer client.Close()

	//ctx = metadata.AppendToOutgoingContext(ctx, "x-goog-foo", "bar")

	t := client.Topic("topic1")

	result := t.Publish(ctx, &pubsub.Message{
		Data: []byte("foo"),
	})

	var wg sync.WaitGroup

	wg.Add(1)
	go func(res *pubsub.PublishResult) {
		defer wg.Done()
		id, err := res.Get(ctx)
		if err != nil {
			fmt.Printf("Failed to publish: %v\n", err)
			return
		}
		fmt.Printf("Published message msg ID: %v\n", id)
	}(result)

	wg.Wait()

}
