// Package msteamsclient is a small Microsoft Teams client library used by
// matterircd (and usable by matterbridge), modeled on matterclient.
package msteamsclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
)

const (
	defaultUserAgent   = "msteamsclient/0.0"
	defaultHTTPTimeout = 30 * time.Second
	postCacheSize      = 2000
	emotionCacheSize   = 2000
	messageChanCap     = 100
)

// UsersCache holds cached users, conversations, teams, and presence data.
// Its structure mirrors matterclient.UsersCache so lock scopes stay separate
// from WebSocket and authentication state.
type UsersCache struct {
	users               map[string]*User
	conversations       map[string]*Conversation
	teams               map[string]*Team
	channelMembers      map[string]map[string]struct{}
	joinedChannels      map[string]struct{}
	channelLastViewedAt map[string]int64
	presences           map[string]*Presence
}

func newUsersCache() *UsersCache {
	return &UsersCache{
		users:               make(map[string]*User),
		conversations:       make(map[string]*Conversation),
		teams:               make(map[string]*Team),
		channelMembers:      make(map[string]map[string]struct{}),
		joinedChannels:      make(map[string]struct{}),
		channelLastViewedAt: make(map[string]int64),
		presences:           make(map[string]*Presence),
	}
}

// Client is a Microsoft Teams client mirroring matterclient's API and lifecycle.
type Client struct {
	sync.RWMutex

	cred Credentials

	User        *User
	Users       *UsersCache
	MessageChan chan *Message

	// Lifecycle & persistence hooks (matching matterclient's callback style).
	OnWsConnect           func()
	OnWsDisconnect        func(err error)
	OnChannelNameResolved func(channelID, name string)
	OnTokenUpdate         func(state TokenState)
	OnAuthPrompt          func(prompt AuthPrompt)

	ForceSyncOnReconnect bool
	CacheClearCutoff     time.Duration
	UserAgent            string
	Timeout              int

	//nolint:containedctx // Tied to the lifecycle of the persistent client session, matching matterclient.
	Ctx         context.Context
	loginCancel context.CancelFunc
	wg          sync.WaitGroup

	connected atomic.Bool

	// Lock ordering: reauthMu -> authMu. Never hold authMu or Client.RWMutex across I/O.
	reauthMu    sync.Mutex
	authMu      sync.RWMutex
	tokenState  TokenState
	scopeTokens map[string]accessTokenEntry

	httpClient *http.Client

	postCache    *lru.Cache[string, *ChatMessage]
	emotionCache *lru.Cache[string, map[string][]ReactionUser]

	lastTypingSent map[string]time.Time

	logger        *logrus.Entry
	rootLogger    *logrus.Logger
	apiLogger     *logrus.Entry
	rootAPILogger *logrus.Logger
}

// New creates a new Microsoft Teams client configured with cred.
func New(cred Credentials) *Client {
	rootLogger, rootAPILogger := newLoggers()
	logger := rootLogger.WithFields(logrus.Fields{"prefix": "msteamsclient"})
	apiLogger := rootAPILogger.WithFields(logrus.Fields{"prefix": "msteamsclient: API"})

	postCache, _ := lru.New[string, *ChatMessage](postCacheSize)
	emotionCache, _ := lru.New[string, map[string][]ReactionUser](emotionCacheSize)

	c := &Client{
		cred:           cred,
		Users:          newUsersCache(),
		MessageChan:    make(chan *Message, messageChanCap),
		UserAgent:      defaultUserAgent,
		scopeTokens:    make(map[string]accessTokenEntry),
		postCache:      postCache,
		emotionCache:   emotionCache,
		lastTypingSent: make(map[string]time.Time),
		rootLogger:     rootLogger,
		logger:         logger,
		rootAPILogger:  rootAPILogger,
		apiLogger:      apiLogger,
	}

	c.initHTTPClient()

	return c
}

func (c *Client) initHTTPClient() {
	timeout := defaultHTTPTimeout
	if c.Timeout > 0 {
		timeout = time.Duration(c.Timeout) * time.Second
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)

	var transport *http.Transport
	if ok {
		transport = baseTransport.Clone()
	} else {
		transport = &http.Transport{}
	}

	if c.cred.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: newAPILogTransport(transport, c.apiLogger),
	}
}

// SetLogAPICalls sets the log level for Teams API call logging.
// Accepted levels match matterclient: 'trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic'.
func (c *Client) SetLogAPICalls(level string) {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		c.logger.Warnf("Failed to parse specified log-level '%s': %#v", level, err)
	} else {
		c.rootAPILogger.SetLevel(l)
	}
}

// SetLogLevel sets the log level for msteamsclient internal logging.
func (c *Client) SetLogLevel(level string) {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		c.logger.Warnf("Failed to parse specified log-level '%s': %#v", level, err)
	} else {
		c.rootLogger.SetLevel(l)
	}
}

// Connected reports whether the client currently has an active session.
func (c *Client) Connected() bool {
	return c.connected.Load()
}

// Me returns a copy of the currently authenticated user profile, or nil before login.
func (c *Client) Me() *User {
	c.RLock()
	defer c.RUnlock()

	if c.User == nil {
		return nil
	}

	cp := *c.User

	return &cp
}

// TokenState returns a snapshot of the current token and regional endpoint state.
func (c *Client) TokenState() TokenState {
	c.authMu.RLock()
	defer c.authMu.RUnlock()

	return c.tokenState
}

// Endpoints returns the discovered regional Microsoft Teams endpoints.
func (c *Client) Endpoints() RegionEndpoints {
	c.authMu.RLock()
	defer c.authMu.RUnlock()

	return c.tokenState.Endpoints
}

// Login authenticates the client against Microsoft Teams.
// Subsequent phases extend Login to perform initial directory sync and start
// the Trouter real-time WebSocket loop.
func (c *Client) Login(ctx context.Context) error {
	c.initHTTPClient()

	loginCtx, cancel := context.WithCancel(ctx)

	c.Lock()
	c.Ctx = loginCtx
	c.loginCancel = cancel
	c.Unlock()

	err := c.Authenticate(loginCtx)
	if err != nil {
		cancel()

		return err
	}

	c.connected.Store(true)

	return nil
}

// Logout terminates background goroutines and marks the client disconnected.
func (c *Client) Logout(_ context.Context) error {
	c.connected.Store(false)

	c.Lock()
	cancel := c.loginCancel
	c.loginCancel = nil
	c.Unlock()

	if cancel != nil {
		cancel()
	}

	c.wg.Wait()

	return nil
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}

	return defaultUserAgent
}
