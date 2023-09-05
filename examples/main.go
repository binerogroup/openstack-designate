package main

import (
	"context"
	"fmt"
	"github.com/libdns/libdns"
	designate "github.com/binerogroup/openstack-designate"
	"log"
	"os"
	"time"
)

func main() {
	// specify proper ZONE name.
	// example: bar.example.com
	zone := os.Getenv("ZONE")
	if zone == "" {
		fmt.Printf("ZONE not set\n")
		return
	}

	provider := designate.Provider{}

	// GET records
	records, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}
	fmt.Println("Records", records)

	// CREATE records
	testName := "foo-libdns."
	add, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{libdns.Record{
		Type:  "TXT",
		Name:  testName + zone,
		Value: fmt.Sprintf("\"Replacement test entry created by libdns %s\"", time.Now()),
		TTL:   time.Duration(600) * time.Second,
	}})

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ADDED", add)

	// UPDATE records
	testName = "foo-libdns."
	edit, err := provider.SetRecords(context.TODO(), zone, []libdns.Record{libdns.Record{
		Type:  "TXT",
		Name:  testName + zone,
		Value: fmt.Sprintf("\"SET1 test entry created by libdns %s\"", time.Now()),
		TTL:   time.Duration(600) * time.Second,
	}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("UPDATED", edit)

	// DELETE records
	testName = "foo-libdns."
	del, err := provider.DeleteRecords(context.TODO(), zone, []libdns.Record{libdns.Record{
		Type: "TXT",
		Name: testName + zone,
	}})

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("DELETED", del)
}
