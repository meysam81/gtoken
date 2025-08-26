package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
	gcm    cipher.AEAD
}

func NewRedisClient() (*RedisClient, error) {
	secretKey := os.Getenv("SECRET_KEY")
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	hash := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &RedisClient{
		client: client,
		gcm:    gcm,
	}, nil
}

func (r *RedisClient) encrypt(plaintext string) (string, error) {
	nonce := make([]byte, r.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := r.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (r *RedisClient) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := r.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextRaw := data[:nonceSize], data[nonceSize:]
	plaintext, err := r.gcm.Open(nil, nonce, ciphertextRaw, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (r *RedisClient) SetSecret(ctx context.Context, key, value string) error {
	encrypted, err := r.encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %w", err)
	}

	return r.client.Set(ctx, key, encrypted, 0).Err()
}

func (r *RedisClient) GetSecret(ctx context.Context, key string) (string, error) {
	encrypted, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}

	return r.decrypt(encrypted)
}

func (r *RedisClient) DeleteSecret(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisClient) Close() error {
	return r.client.Close()
}
