package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type sessionRepository struct {
	client *redis.Client
	prefix string
}

func NewSessionRepository(client *redis.Client) SessionRepository {
	return &sessionRepository{
		client: client,
		prefix: "session",
	}
}

// SaveSession сохраняет сессию в Redis с TTL
func (r *sessionRepository) SaveSession(ctx context.Context, session *Session) error {
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := r.buildKey(session.SessionID)

	// Сохраняем сессию с TTL
	expiration := time.Until(session.ExpiresAt)
	if err := r.client.SetEx(ctx, key, sessionData, expiration).Err(); err != nil {
		return fmt.Errorf("failed to save session to redis: %w", err)
	}

	// Добавляем в набор сессий пользователя для быстрого поиска
	userSessionsKey := r.buildUserSessionsKey(session.UserID)
	if err := r.client.SAdd(ctx, userSessionsKey, session.SessionID).Err(); err != nil {
		return fmt.Errorf("failed to add session to user set: %w", err)
	}

	// Устанавливаем TTL для набора сессий пользователя
	if err := r.client.ExpireAt(ctx, userSessionsKey, session.ExpiresAt).Err(); err != nil {
		return fmt.Errorf("failed to set expiration for user sessions: %w", err)
	}

	return nil
}

// GetSession получает сессию по ID
func (r *sessionRepository) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	key := r.buildKey(sessionID)

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session from redis: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// BlockSession блокирует сессию
func (r *sessionRepository) BlockSession(ctx context.Context, sessionID string) error {
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.IsBlocked = true
	return r.SaveSession(ctx, session)
}

// DeleteSession полностью удаляет сессию
func (r *sessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	// Сначала получаем сессию чтобы узнать userID
	session, err := r.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	key := r.buildKey(sessionID)

	// Удаляем сессию
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Удаляем из набора сессий пользователя
	userSessionsKey := r.buildUserSessionsKey(session.UserID)
	if err := r.client.SRem(ctx, userSessionsKey, sessionID).Err(); err != nil {
		// Логируем, но не прерываем выполнение
		fmt.Printf("warning: failed to remove session from user set: %v\n", err)
	}

	return nil
}

// GetUserSessions возвращает все активные сессии пользователя
func (r *sessionRepository) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	userSessionsKey := r.buildUserSessionsKey(userID)

	sessionIDs, err := r.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	var sessions []*Session
	for _, sessionID := range sessionIDs {
		session, err := r.GetSession(ctx, sessionID)
		if err != nil {
			// Пропускаем невалидные сессии, но логируем
			fmt.Printf("warning: failed to get session %s: %v\n", sessionID, err)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// BlockAllUserSessions блокирует все сессии пользователя
func (r *sessionRepository) BlockAllUserSessions(ctx context.Context, userID string) error {
	sessions, err := r.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if !session.IsBlocked {
			session.IsBlocked = true
			if err := r.SaveSession(ctx, session); err != nil {
				// Логируем ошибку, но продолжаем блокировать остальные сессии
				fmt.Printf("warning: failed to block session %s: %v\n", session.SessionID, err)
			}
		}
	}

	return nil
}

// CleanupExpiredSessions очищает просроченные сессии
func (r *sessionRepository) CleanupExpiredSessions(ctx context.Context) error {
	// Redis автоматически удаляет ключи с истекшим TTL
	// Этот метод может быть полезен для дополнительной очистки наборов пользователей

	// Можно добавить логику для очистки orphaned session IDs из user sets
	// но в большинстве случаев это не требуется благодаря TTL

	return nil
}

// Вспомогательные методы для построения ключей
func (r *sessionRepository) buildKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", r.prefix, sessionID)
}

func (r *sessionRepository) buildUserSessionsKey(userID string) string {
	return fmt.Sprintf("user_sessions:%s", userID)
}
