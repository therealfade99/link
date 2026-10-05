package devstream

import (
    "context"
    "errors"
    "log/slog"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/gorilla/websocket"
    "github.com/redis/go-redis/v9"
)

const (
    channelPrefix         = "dev:events:"
    sendBuffer            = 64
    readLimit             = 512
    writeWait             = 10 * time.Second
    pongWait              = 60 * time.Second
    pingEvery             = 50 * time.Second
    maxClientsPerMerchant = 5
    bufferSize            = 1024
    handshakeWait         = 10 * time.Second
)

type client struct {
    send    chan []byte
    done    chan struct{}
    once    sync.Once
    created time.Time
}

func (c *client) stop() { c.once.Do(func() { close(c.done) }) }

type Hub struct {
    mu       sync.RWMutex
    clients  map[string]map[*client]struct{}
    upgrader websocket.Upgrader
}

func NewHub() *Hub {
    return &Hub{
        clients: map[string]map[*client]struct{}{},
        upgrader: websocket.Upgrader{
            ReadBufferSize:   bufferSize,
            WriteBufferSize:  bufferSize,
            HandshakeTimeout: handshakeWait,
        },
    }
}

func Publish(ctx context.Context, rdb redis.Cmdable, merchantID string, msg []byte) error {
    return rdb.Publish(ctx, channelPrefix+merchantID, msg).Err()
}

func (h *Hub) Subscribe(ctx context.Context, rdb *redis.Client) error {
    sub := rdb.PSubscribe(ctx, channelPrefix+"*")
    defer sub.Close()

    if _, err := sub.Receive(ctx); err != nil {
        return err
    }

    ch := sub.Channel()
    for {
        select {
        case <-ctx.Done():
            h.closeAll()
            return ctx.Err()
        case m, ok := <-ch:
            if !ok {
                h.closeAll()
                return errors.New("devstream: redis subscription closed")
            }
            h.deliver(strings.TrimPrefix(m.Channel, channelPrefix), []byte(m.Payload))
        }
    }
}

func (h *Hub) closeAll() {
    h.mu.RLock()
    defer h.mu.RUnlock()
    for _, set := range h.clients {
        for c := range set {
            c.stop()
        }
    }
}

func (h *Hub) Serve(w http.ResponseWriter, r *http.Request, merchantID string) {
    conn, err := h.upgrader.Upgrade(w, r, nil)
    if err != nil {
        slog.Warn("devstream: upgrade failed", "merchant", merchantID, "err", err)
        return
    }

    c := &client{
        send:    make(chan []byte, sendBuffer),
        done:    make(chan struct{}),
        created: time.Now(),
    }
    c.send <- []byte(`{"type":"connected"}`)
    h.add(merchantID, c)

    go c.writeLoop(conn)
    c.readLoop(conn)

    h.remove(merchantID, c)
    c.stop()
    _ = conn.Close()
}

func (h *Hub) deliver(merchantID string, msg []byte) {
    h.mu.RLock()
    defer h.mu.RUnlock()
    for c := range h.clients[merchantID] {
        select {
        case c.send <- msg:
        default:
            slog.Warn("devstream: dropping slow client", "merchant", merchantID)
            c.stop()
        }
    }
}

func (h *Hub) add(merchantID string, c *client) {
    h.mu.Lock()
    defer h.mu.Unlock()
    set := h.clients[merchantID]
    if set == nil {
        set = map[*client]struct{}{}
        h.clients[merchantID] = set
    }
    if len(set) >= maxClientsPerMerchant {
        var oldest *client
        for existing := range set {
            if oldest == nil || existing.created.Before(oldest.created) {
                oldest = existing
            }
        }
        oldest.stop()
        delete(set, oldest)
        slog.Info("devstream: evicted oldest connection", "merchant", merchantID)
    }
    set[c] = struct{}{}
}

func (h *Hub) remove(merchantID string, c *client) {
    h.mu.Lock()
    defer h.mu.Unlock()
    set := h.clients[merchantID]
    delete(set, c)
    if len(set) == 0 {
        delete(h.clients, merchantID)
    }
}

func (c *client) readLoop(conn *websocket.Conn) {
    conn.SetReadLimit(readLimit)
    _ = conn.SetReadDeadline(time.Now().Add(pongWait))
    conn.SetPongHandler(func(string) error {
        return conn.SetReadDeadline(time.Now().Add(pongWait))
    })
    for {
        if _, _, err := conn.ReadMessage(); err != nil {
            return
        }
    }
}

func (c *client) writeLoop(conn *websocket.Conn) {
    ticker := time.NewTicker(pingEvery)
    defer ticker.Stop()
    for {
        select {
        case msg := <-c.send:
            _ = conn.SetWriteDeadline(time.Now().Add(writeWait))
            if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
                _ = conn.Close()
                return
            }
        case <-ticker.C:
            _ = conn.SetWriteDeadline(time.Now().Add(writeWait))
            if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
                _ = conn.Close()
                return
            }
        case <-c.done:
            _ = conn.WriteControl(websocket.CloseMessage,
                websocket.FormatCloseMessage(websocket.CloseGoingAway, "closing"),
                time.Now().Add(writeWait))
            _ = conn.Close()
            return
        }
    }
}