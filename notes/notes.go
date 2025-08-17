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
	ID      primitive.ObjectID `json:"id" bson:"_id"`
	Content string             `json:"content" bson:"content"`
	Color   string             `json:"color" bson:"color"`
}

func GetNotes(
	ctx context.Context,
	notesDB *mongo.Collection,
) ([]Note, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cursor, err := notesDB.Find(dbCtx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find notes; %w", err)
	}
	defer cursor.Close(dbCtx)

	notes := make([]Note, 0)
	if err = cursor.All(dbCtx, &notes); err != nil {
		return nil, fmt.Errorf("failed to decode notes; %w", err)
	}

	// convert ObjectID to string for JSON
	// for i := range notes {
	// 	notes[i].ID = notes[i].ID
	// }

	return notes, nil
}

func CreateNote(
	ctx context.Context,
	notesDB *mongo.Collection,
	content string,
	color string,
) error {
	if color == "" {
		color = getRandomColor() // Fallback to random color if not provided
	}
	newNote := Note{
		ID:      primitive.NewObjectID(),
		Content: content,
		Color:   color,
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
	id string,
	content string,
	color string,
) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("failed to get object ID from hex; %w", err)
	}

	updateFields := bson.M{"content": content}
	if color != "" {
		updateFields["color"] = color // only update color if provided
	}

	update := bson.M{"$set": updateFields}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := notesDB.UpdateOne(dbCtx, bson.M{"_id": objectID}, update)
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
	id string,
) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("failed to get object ID from hex; %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := notesDB.DeleteOne(ctx, bson.M{"_id": objectID})
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
