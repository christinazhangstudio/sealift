package main

import (
	"context"
	"log/slog"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ensureIndexes creates the indexes the application's queries actually use.
//
// Previously only three existed, and two of them indexed the wrong field for
// the query that runs: revoked_tokens and oauth_states had TTL indexes on
// createdAt but are looked up by jti and state. Everything else — including
// ebay_accounts, which is read on every single eBay API call — was a full
// collection scan. That is invisible at a handful of documents and becomes the
// dominant cost well before a hundred tenants.
//
// Index creation is idempotent. Failures are logged rather than discarded: a
// unique index that fails to build (say, because duplicates already exist) is
// something an operator needs to know about, not something to silently lose.
func ensureIndexes(ctx context.Context, db *mongo.Database) {
	type indexSpec struct {
		collection string
		model      mongo.IndexModel
		// why documents the query this serves, for whoever reads this next.
		why string
	}

	day := int32(24 * 60 * 60)

	specs := []indexSpec{
		{
			collection: "ebay_accounts",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "sealift_user_id", Value: 1}, {Key: "user", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("tenant_seller_unique"),
			},
			why: "auth.GetToken on every eBay call, GetUsers, SSE ownership checks",
		},
		{
			collection: "inbox",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "user", Value: 1}, {Key: "createdAt", Value: -1}},
				Options: options.Index().SetName("user_recent"),
			},
			why: "GetPastNotifications: filter by seller, sort newest first",
		},
		{
			collection: "inbox",
			model: mongo.IndexModel{
				Keys: bson.D{
					{Key: "user", Value: 1},
					{Key: "payload.notification.notificationId", Value: 1},
				},
				Options: options.Index().SetName("user_notification"),
			},
			why: "trash / mark read / delete, which match on both fields",
		},
		{
			collection: "revoked_tokens",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "jti", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("jti_unique"),
			},
			why: "revocation check on every authenticated request; unique also makes " +
				"the duplicate-key branch in handleRevoke reachable",
		},
		{
			collection: "oauth_states",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "state", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("state_unique"),
			},
			why: "the OAuth callback consumes a state token by value",
		},
		{
			collection: "password_resets",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "tokenHash", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("token_unique"),
			},
			why: "reset links are redeemed by token hash",
		},
		{
			collection: "notification_tests",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "notificationId", Value: 1}},
				Options: options.Index().SetUnique(true).SetName("notification_test_unique"),
			},
			why: "match an eBay test payload to the seller that requested it",
		},
		{
			collection: "knowledge_base",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "model", Value: 1}},
				Options: options.Index().SetName("embedding_model"),
			},
			why: "retrieval only considers vectors from the current embedding model",
		},

		// TTL indexes: these expire documents, they don't serve lookups. Left
		// unnamed so they match the default-named ones already in the database —
		// asking for a different name on the same keys is a conflict, not a
		// change.
		{
			collection: "revoked_tokens",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "createdAt", Value: 1}},
				Options: options.Index().SetExpireAfterSeconds(day),
			},
			why: "revoked tokens are irrelevant once the JWT itself expires",
		},
		{
			collection: "oauth_states",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "createdAt", Value: 1}},
				Options: options.Index().SetExpireAfterSeconds(15 * 60),
			},
			why: "abandoned OAuth attempts shouldn't accumulate",
		},
		{
			collection: "password_resets",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "createdAt", Value: 1}},
				Options: options.Index().SetExpireAfterSeconds(2 * 60 * 60),
			},
			why: "reset links are valid for an hour; clean up shortly after",
		},
		{
			collection: "notification_tests",
			model: mongo.IndexModel{
				Keys:    bson.D{{Key: "createdAt", Value: 1}},
				Options: options.Index().SetExpireAfterSeconds(10 * 60),
			},
			why: "test-delivery correlation is only needed while eBay queues the payload",
		},
	}

	for _, spec := range specs {
		if _, err := db.Collection(spec.collection).Indexes().CreateOne(ctx, spec.model); err != nil {
			slog.Error("failed to create index",
				"err", err, "collection", spec.collection, "purpose", spec.why)
		}
	}

	ensureEmailIndex(ctx, db)

	slog.Info("index check complete")
}

// ensureEmailIndex rebuilds the tenant email index with a case-insensitive
// collation.
//
// Sign-in and registration query email with a strength-2 collation, and MongoDB
// cannot use an index whose collation differs from the query's — so the original
// plain index was never used and every login scanned the collection. Matching
// the collation also makes uniqueness case-insensitive, which is what the
// application already enforces in application code.
func ensureEmailIndex(ctx context.Context, db *mongo.Database) {
	const wanted = "email_ci_unique"
	col := db.Collection("sealift_users")

	cursor, err := col.Indexes().List(ctx)
	if err != nil {
		slog.Error("could not list indexes on sealift_users", "err", err)
		return
	}
	var existing []bson.M
	if err := cursor.All(ctx, &existing); err != nil {
		slog.Error("could not read indexes on sealift_users", "err", err)
		return
	}

	for _, idx := range existing {
		if name, _ := idx["name"].(string); name == wanted {
			return // already in place
		}
	}

	// Create the replacement before dropping the old one, so uniqueness is never
	// unenforced in between.
	if _, err := col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "email", Value: 1}},
		Options: options.Index().
			SetUnique(true).
			SetName(wanted).
			SetCollation(&options.Collation{Locale: "en", Strength: 2}),
	}); err != nil {
		// Most likely cause: two accounts whose emails differ only by case.
		// Leaving the old index in place is the safe outcome.
		slog.Error("could not create case-insensitive email index; "+
			"check for accounts whose emails differ only by case", "err", err)
		return
	}

	for _, idx := range existing {
		name, _ := idx["name"].(string)
		if name == "email_1" {
			if _, err := col.Indexes().DropOne(ctx, name); err != nil {
				slog.Warn("created the case-insensitive email index but could not drop the old one",
					"err", err, "index", name)
			} else {
				slog.Info("replaced the case-sensitive email index with a collated one")
			}
		}
	}
}
