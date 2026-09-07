package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

const rememberedSessionLifetime = int32(30 * 24 * 60 * 60)

func revocationTTLIndex(name string, seconds int32) bson.D {
	return bson.D{
		{Key: "name", Value: name},
		{Key: "key", Value: bson.D{{Key: "createdAt", Value: 1}}},
		{Key: "expireAfterSeconds", Value: seconds},
	}
}

func TestEnsureRevocationRetentionMigratesShortTTL(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, name := range []string{"createdAt_1", "custom_revocation_ttl"} {
		mt.Run(name, func(mt *mtest.T) {
			mt.AddMockResponses(
				mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch,
					revocationTTLIndex(name, 24*60*60)),
				mtest.CreateSuccessResponse(),
				mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch,
					revocationTTLIndex(name, rememberedSessionLifetime)),
			)
			if err := ensureRevocationRetention(context.Background(), mt.DB); err != nil {
				mt.Fatal(err)
			}
			// On a subsequent startup the migrated index requires no writes.
			if err := ensureRevocationRetention(context.Background(), mt.DB); err != nil {
				mt.Fatalf("migration was not idempotent: %v", err)
			}
			events := mt.GetAllStartedEvents()
			if len(events) != 3 || events[0].CommandName != "listIndexes" || events[1].CommandName != "collMod" || events[2].CommandName != "listIndexes" {
				mt.Fatalf("expected list, in-place migration, then read-only recheck; got %#v", events)
			}
			command := events[1].Command
			if got := command.Lookup("collMod").StringValue(); got != "revoked_tokens" {
				mt.Fatalf("modified wrong collection: %q", got)
			}
			if got := command.Lookup("index", "name").StringValue(); got != name {
				mt.Fatalf("changed index identity: %q, want %q", got, name)
			}
			if got := command.Lookup("index", "expireAfterSeconds").Int32(); got < rememberedSessionLifetime {
				mt.Fatalf("retention %ds does not cover a 30-day signed token", got)
			}
		})
	}
}

func TestEnsureRevocationRetentionPreservesSufficientRetention(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name  string
		index bson.D
	}{
		{"30 days", revocationTTLIndex("createdAt_1", rememberedSessionLifetime)},
		{"longer retention", revocationTTLIndex("createdAt_1", 45*24*60*60)},
		{"indefinite retention", bson.D{
			{Key: "name", Value: "createdAt_1"},
			{Key: "key", Value: bson.D{{Key: "createdAt", Value: 1}}},
		}},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch, tc.index))
			if err := ensureRevocationRetention(context.Background(), mt.DB); err != nil {
				mt.Fatal(err)
			}
			if events := mt.GetAllStartedEvents(); len(events) != 1 || events[0].CommandName != "listIndexes" {
				mt.Fatalf("sufficient retention must not be modified: %#v", events)
			}
		})
	}
}

func TestEnsureRevocationRetentionCreatesMissingIndex(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, missingCollection := range []bool{false, true} {
		name := "existing collection"
		if missingCollection {
			name = "new database"
		}
		mt.Run(name, func(mt *mtest.T) {
			if missingCollection {
				mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 26, Name: "NamespaceNotFound", Message: "collection does not exist"}))
			} else {
				mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch, bson.D{
					{Key: "name", Value: "jti_unique"},
					{Key: "key", Value: bson.D{{Key: "jti", Value: 1}}},
				}))
			}
			mt.AddMockResponses(mtest.CreateSuccessResponse())
			if err := ensureRevocationRetention(context.Background(), mt.DB); err != nil {
				mt.Fatal(err)
			}
			events := mt.GetAllStartedEvents()
			if len(events) != 2 || events[1].CommandName != "createIndexes" {
				mt.Fatalf("missing TTL index was not created: %#v", events)
			}
			command := events[1].Command
			if command.Lookup("createIndexes").StringValue() != "revoked_tokens" {
				mt.Fatal("created index on the wrong collection")
			}
			models, err := command.Lookup("indexes").Array().Values()
			if err != nil || len(models) != 1 {
				mt.Fatalf("unexpected index models: %v, %v", models, err)
			}
			index := models[0].Document()
			if index.Lookup("name").StringValue() != "createdAt_1" || index.Lookup("key", "createdAt").Int32() != 1 {
				mt.Fatalf("unexpected TTL index: %v", index)
			}
			if got := index.Lookup("expireAfterSeconds").Int32(); got < rememberedSessionLifetime {
				mt.Fatalf("new retention %ds does not cover a 30-day signed token", got)
			}
		})
	}
}

func TestEnsureRevocationRetentionExtendsEveryShortTTL(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	mt.Run("multiple createdAt indexes", func(mt *mtest.T) {
		secondIndex := revocationTTLIndex("createdAt_desc", 2*24*60*60)
		secondIndex[1].Value = bson.D{{Key: "createdAt", Value: -1}}
		mt.AddMockResponses(
			mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch,
				revocationTTLIndex("createdAt_1", 24*60*60), secondIndex),
			mtest.CreateSuccessResponse(), mtest.CreateSuccessResponse(),
		)
		if err := ensureRevocationRetention(context.Background(), mt.DB); err != nil {
			mt.Fatal(err)
		}
		events := mt.GetAllStartedEvents()
		if len(events) != 3 || events[1].CommandName != "collMod" || events[2].CommandName != "collMod" {
			mt.Fatalf("left a short TTL that can still delete revoked JTIs: %#v", events)
		}
	})
}

func TestEnsureRevocationRetentionPropagatesErrors(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, operation := range []string{"list", "extend", "create"} {
		mt.Run(operation, func(mt *mtest.T) {
			if operation == "extend" {
				mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch,
					revocationTTLIndex("createdAt_1", 24*60*60)))
			} else if operation == "create" {
				mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+".revoked_tokens", mtest.FirstBatch))
			}
			mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 13, Name: "Unauthorized", Message: "migration denied"}))
			err := ensureRevocationRetention(context.Background(), mt.DB)
			var commandErr mongo.CommandError
			if !errors.As(err, &commandErr) || commandErr.Code != 13 || !strings.Contains(err.Error(), operation) {
				mt.Fatalf("startup needs the %s failure, got %v", operation, err)
			}
			for _, event := range mt.GetAllStartedEvents() {
				if event.CommandName == "dropIndexes" || event.CommandName == "delete" {
					mt.Fatalf("migration must not delete indexes or records on failure: %s", event.CommandName)
				}
			}
		})
	}
}
