package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
)

// ClientConfig defines the configuration for SOCKS5 client
type ClientConfig struct {
	Host string
	Port int
	User *User
}

// Client represents a SOCKS5 client
type Client struct {
	config *ClientConfig
}

// NewClient creates a new SOCKS5 client with the given configuration
func NewClient(config *ClientConfig) *Client {
	return &Client{
		config: config,
	}
}

// NewClientFromURL creates a new SOCKS5 client from a URL string
func NewClientFromURL(rawURL string) (*Client, error) {
	// Parse the URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	if u.Scheme != "socks" && u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	// Parse port
	port := u.Port()
	if port == "" {
		port = "1080" // Default SOCKS5 port
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}
	// Parse authentication info
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	config := &ClientConfig{
		Host: u.Hostname(),
		Port: portNum,
		User: &User{
			Username: username,
			Password: password,
		},
	}

	return NewClient(config), nil
}

// Connect establishes a connection to the SOCKS5 server
func (c *Client) connect() (net.Conn, error) {
	// Connect to the SOCKS server
	addr := net.JoinHostPort(c.config.Host, strconv.Itoa(c.config.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 server: %v", err)
	}
	// Send version identifier/method selection message
	methods := []byte{NO_AUTH}
	if c.config.User.Username != "" && c.config.User.Password != "" {
		methods = append(methods, USERNAME_AUTH)
	}
	data := []byte{SOCKS5, byte(len(methods))}
	data = append(data, methods...)
	if _, err := conn.Write(data); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send method selection: %v", err)
	}

	// Receive server's response
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read server response: %v", err)
	}

	version := resp[0]
	if version != SOCKS5 {
		conn.Close()
		return nil, fmt.Errorf("unsupported protocol version: %v", version)
	}

	// Handle authentication
	authType := resp[1]
	switch authType {
	case NO_AUTH:
		// No authentication required
		return conn, nil

	case USERNAME_AUTH:
		if c.config.User.IsEmpty() {
			conn.Close()
			return nil, errors.New("server requires authentication but no credentials provided")
		}

		// Send username/password authentication
		auth := []byte{0x01} // auth version
		auth = append(auth, byte(len(c.config.User.Username)))
		auth = append(auth, []byte(c.config.User.Username)...)
		auth = append(auth, byte(len(c.config.User.Password)))
		auth = append(auth, []byte(c.config.User.Password)...)

		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send authentication: %v", err)
		}

		// Read authentication response
		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read auth response: %v", err)
		}

		if authResp[1] != SUCCESS {
			conn.Close()
			return nil, errors.New("authentication failed")
		}

		return conn, nil

	case NO_ACCEPT_METHODS:
		conn.Close()
		return nil, errors.New("no acceptable authentication methods")

	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

// Dial connects to the address on the named network via the SOCKS5 proxy
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		// These are supported
	default:
		return nil, errors.New("unsupported network type")
	}

	// Connect to the SOCKS server
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}

	// Parse the target address
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	// Build connect request
	req := []byte{SOCKS5, CONNECT, 0x00}

	// Add address
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		req = append(req, DOMAIN)
		req = append(req, byte(len(host)))
		req = append(req, host...)
	} else if ip4 := ip.To4(); ip4 != nil {
		req = append(req, IPv4)
		req = append(req, ip4...)
	} else {
		req = append(req, IPv6)
		req = append(req, ip.To16()...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	// Send request
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != SUCCESS {
		conn.Close()
		return nil, fmt.Errorf("connection failed, status: %d", resp[1])
	}
	// Skip the bound address and port in the response
	addressType := resp[3]
	switch addressType {
	case IPv4:
		if _, err := io.CopyN(io.Discard, conn, 6); err != nil {
			conn.Close()
			return nil, err
		}
	case DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(lenByte[0])+2); err != nil {
			conn.Close()
			return nil, err
		}
	case IPv6:
		if _, err := io.CopyN(io.Discard, conn, 18); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported address type in response: %v", addressType)
	}

	return conn, nil
}
