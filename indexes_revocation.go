package main

import (
	"context"
	"fmt"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// revokedTokenRetentionSeconds must cover the frontend's maximum signed JWT
// lifetime: 30 days for Remember Device, 24 hours otherwise. Retention starts
// when the JTI is revoked, so no JWT can outlive its revocation record.
// Keep this in sync if the frontend ever increases its maximum token lifetime.
const revokedTokenRetentionSeconds int32 = 30 * 24 * 60 * 60

// ensureRevocationRetention extends existing TTL indexes in place. CreateOne
// cannot update expireAfterSeconds on an existing index; simply changing the
// index specification would leave deployed databases expiring JTIs after 24h.
// A failure is returned to startup because that would revive signed-out tokens.
func ensureRevocationRetention(ctx context.Context, db *mongo.Database) error {
	col := db.Collection("revoked_tokens")
	indexes, err := col.Indexes().ListSpecifications(ctx)
	if err != nil {
		return fmt.Errorf("list revoked token indexes; %w", err)
	}

	found := false
	for _, index := range indexes {
		keys, err := index.KeysDocument.Elements()
		if err != nil {
			return fmt.Errorf("read revoked token index %q; %w", index.Name, err)
		}
		if len(keys) != 1 || keys[0].Key() != "createdAt" {
			continue
		}
		found = true
		// No TTL means records are retained indefinitely. Preserve this and
		// any longer retention explicitly configured by the operator.
		if index.ExpireAfterSeconds == nil || *index.ExpireAfterSeconds >= revokedTokenRetentionSeconds {
			continue
		}
		if err := db.RunCommand(ctx, bson.D{
			{Key: "collMod", Value: col.Name()},
			{Key: "index", Value: bson.D{
				{Key: "name", Value: index.Name},
				{Key: "expireAfterSeconds", Value: revokedTokenRetentionSeconds},
			}},
		}).Err(); err != nil {
			return fmt.Errorf("extend revoked token TTL index %q; %w", index.Name, err)
		}
		slog.Info("extended revoked token retention", "index", index.Name, "seconds", revokedTokenRetentionSeconds)
	}
	if found {
		return nil
	}

	if _, err := col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "createdAt", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(revokedTokenRetentionSeconds),
	}); err != nil {
		return fmt.Errorf("create revoked token TTL index; %w", err)
	}
	return nil
}
