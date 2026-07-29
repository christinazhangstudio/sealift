package main

import (
	"context"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.tesla.com/chrzhang/sealift/secrets"
)

// encryptStoredCredentials rewrites credentials that predate encryption.
//
// Decryption tolerates plaintext, so the application works either way — but
// leaving old rows in the clear would mean "encrypted at rest" is only true for
// accounts created after the change. This runs at startup, skips anything
// already encrypted, and is safe to run repeatedly.
func encryptStoredCredentials(ctx context.Context, db *mongo.Database) {
	if !secrets.Enabled() {
		slog.Warn("CREDENTIAL_ENCRYPTION_KEY is not set — eBay credentials and tokens " +
			"are being stored in plaintext")
		return
	}

	users := migrateField(ctx, db.Collection("sealift_users"),
		"ebayDeveloperConfig.certId", func(doc bson.M) string {
			cfg, ok := doc["ebayDeveloperConfig"].(bson.M)
			if !ok {
				return ""
			}
			value, _ := cfg["certId"].(string)
			return value
		})

	accessTokens := migrateField(ctx, db.Collection("ebay_accounts"),
		"access_token", func(doc bson.M) string {
			value, _ := doc["access_token"].(string)
			return value
		})

	refreshTokens := migrateField(ctx, db.Collection("ebay_accounts"),
		"refresh_token", func(doc bson.M) string {
			value, _ := doc["refresh_token"].(string)
			return value
		})

	if users+accessTokens+refreshTokens > 0 {
		slog.Info("encrypted credentials that were stored in plaintext",
			"certIds", users, "accessTokens", accessTokens, "refreshTokens", refreshTokens)
	} else {
		slog.Info("credential encryption active; nothing left in plaintext")
	}
}

// migrateField encrypts one field across a collection, in place.
func migrateField(
	ctx context.Context,
	col *mongo.Collection,
	field string,
	read func(bson.M) string,
) int {
	cursor, err := col.Find(ctx, bson.M{})
	if err != nil {
		slog.Error("credential migration: could not read collection",
			"err", err, "collection", col.Name(), "field", field)
		return 0
	}
	defer cursor.Close(ctx)

	var docs []bson.M
	if err := cursor.All(ctx, &docs); err != nil {
		slog.Error("credential migration: could not decode documents",
			"err", err, "collection", col.Name())
		return 0
	}

	migrated := 0
	for _, doc := range docs {
		plaintext := read(doc)
		if plaintext == "" || secrets.IsEncrypted(plaintext) {
			continue
		}

		encrypted, err := secrets.Encrypt(plaintext)
		if err != nil {
			slog.Error("credential migration: encryption failed",
				"err", err, "collection", col.Name(), "field", field)
			continue
		}

		if _, err := col.UpdateOne(ctx,
			bson.M{"_id": doc["_id"]},
			bson.M{"$set": bson.M{field: encrypted}},
		); err != nil {
			slog.Error("credential migration: write failed",
				"err", err, "collection", col.Name(), "field", field)
			continue
		}
		migrated++
	}
	return migrated
}
