package notes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Note struct {
	ID            primitive.ObjectID `json:"id" bson:"_id"`
	SealiftUserID string             `json:"sealift_user_id" bson:"sealift_user_id"`
	Content       string             `json:"content" bson:"content"`
	Color         string             `json:"color" bson:"color"`
}

func GetNotes(
	ctx context.Context,
	notesDB *mongo.Collection,
	sealiftUserID string,
) ([]Note, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.M{}
	if sealiftUserID != "" {
		filter["sealift_user_id"] = sealiftUserID
	}

	result, err := notesDB.Find(dbCtx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find notes; %w", err)
	}
	defer result.Close(dbCtx)

	notes := make([]Note, 0)
	if err = result.All(dbCtx, &notes); err != nil {
		return nil, fmt.Errorf("failed to decode notes; %w", err)
	}

	return notes, nil
}

func CreateNote(
	ctx context.Context,
	notesDB *mongo.Collection,
	sealiftUserID string,
	content string,
	color string,
) error {
	if color == "" {
		color = getRandomColor() // Fallback to random color if not provided
	}
	newNote := Note{
		ID:            primitive.NewObjectID(),
		SealiftUserID: sealiftUserID,
		Content:       content,
		Color:         color,
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := notesDB.InsertOne(dbCtx, newNote)
	if err != nil {
		return fmt.Errorf("failed to create note; %w", err)
	}

	return nil
}

func UpdateNote(
	ctx context.Context,
	notesDB *mongo.Collection,
	sealiftUserID string,
	id string,
	content string,
	color string,
) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("failed to get object ID from hex; %w", err)
	}

	filter := bson.M{"_id": objectID}
	if sealiftUserID != "" {
		filter["sealift_user_id"] = sealiftUserID
	}

	updateFields := bson.M{"content": content}
	if color != "" {
		updateFields["color"] = color // only update color if provided
	}

	update := bson.M{"$set": updateFields}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := notesDB.UpdateOne(dbCtx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update note; %w", err)
	}

	if result.MatchedCount == 0 {
		return errors.New("failed to find note")
	}

	return nil
}

func DeleteNote(
	ctx context.Context,
	notesDB *mongo.Collection,
	sealiftUserID string,
	id string,
) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("failed to get object ID from hex; %w", err)
	}

	filter := bson.M{"_id": objectID}
	if sealiftUserID != "" {
		filter["sealift_user_id"] = sealiftUserID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := notesDB.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete note; %w", err)
	}

	if result.DeletedCount == 0 {
		return errors.New("failed to verify note was deleted")
	}

	return nil
}

// getRandomColor returns a random Tailwind CSS color class
func getRandomColor() string {
	colors := []string{
		"bg-yellow-100",
		"bg-pink-200",
		"bg-green-200",
		"bg-blue-200",
		"bg-purple-200",
	}
	return colors[int(time.Now().UnixNano())%len(colors)]
}
