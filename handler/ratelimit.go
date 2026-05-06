package handler

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

const (
	ipWindow          = time.Minute
	ipMaxPerWindow    = 5
	emailMaxFails     = 5
	emailLockDuration = 15 * time.Minute
)

type rateLimiter struct {
	mu             sync.Mutex
	ipAttempts     map[string][]time.Time
	emailFailCount map[string]int
	emailLockUntil map[string]time.Time
}

var loginLimiter = &rateLimiter{
	ipAttempts:     make(map[string][]time.Time),
	emailFailCount: make(map[string]int),
	emailLockUntil: make(map[string]time.Time),
}

// allowLogin returns nil if the attempt may proceed, or an HTTP error otherwise.
// It also records the attempt against the IP window.
func (r *rateLimiter) allowLogin(ip, email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-ipWindow)
	kept := r.ipAttempts[ip][:0]
	for _, t := range r.ipAttempts[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= ipMaxPerWindow {
		r.ipAttempts[ip] = kept
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many login attempts; try again later")
	}
	r.ipAttempts[ip] = append(kept, now)

	if until, locked := r.emailLockUntil[email]; locked {
		if now.Before(until) {
			return echo.NewHTTPError(http.StatusTooManyRequests, "Account temporarily locked; try again later")
		}
		delete(r.emailLockUntil, email)
		delete(r.emailFailCount, email)
	}
	return nil
}

// recordFailure increments the per-email failure counter and locks the account
// once the threshold is reached. Should only be called when the supplied
// credentials matched a real account.
func (r *rateLimiter) recordFailure(email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.emailFailCount[email]++
	if r.emailFailCount[email] >= emailMaxFails {
		r.emailLockUntil[email] = time.Now().Add(emailLockDuration)
	}
}

func (r *rateLimiter) recordSuccess(email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.emailFailCount, email)
	delete(r.emailLockUntil, email)
}
