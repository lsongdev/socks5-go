package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	// Protocol version
	SOCKS4 = 0x04
	SOCKS5 = 0x05

	// Authentication methods
	NO_AUTH           = 0x00
	USERNAME_AUTH     = 0x02
	NO_ACCEPT_METHODS = 0xFF

	// Auth version
	AUTH_VERSION = 0x01

	// Commands
	CONNECT = 0x01
	BIND    = 0x02
	UDP     = 0x03

	// Address types
	IPv4   = 0x01
	DOMAIN = 0x03
	IPv6   = 0x04

	// Response codes
	SUCCESS                    = 0x00
	FAILURE                    = 0x01
	NOT_ALLOWED                = 0x02
	NETWORK_UNREACHABLE        = 0x03
	HOST_UNREACHABLE           = 0x04
	CONNECTION_REFUSED         = 0x05
	TTL_EXPIRED                = 0x06
	COMMAND_NOT_SUPPORTED      = 0x07
	ADDRESS_TYPE_NOT_SUPPORTED = 0x08
)

type User struct {
	Username string
	Password string
}

func (u *User) IsEmpty() bool {
	return u.Username == "" && u.Password == ""
}

// MethodSelection represents the client's method selection message
type MethodSelection struct {
	net.Conn

	Version  byte
	NMethods byte
	Methods  []byte
}

// ParseMethodSelection reads and parses the client's method selection message
func ParseMethodSelection(conn net.Conn) (*MethodSelection, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != SOCKS5 {
		return nil, fmt.Errorf("unsupported protocol version: %v", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	// log.Println("header, methods", header, methods)

	return &MethodSelection{
		Conn:     conn,
		Version:  header[0],
		NMethods: header[1],
		Methods:  methods,
	}, nil
}

// ReadAuthPacket reads username/password authentication packet
func (mc *MethodSelection) ReadUser() (user User, err error) {
	// Read version
	version := make([]byte, 1)
	if _, err = io.ReadFull(mc, version); err != nil {
		return
	}

	if version[0] != AUTH_VERSION {
		return
	}

	// Read username length
	ulen := make([]byte, 1)
	if _, err = io.ReadFull(mc, ulen); err != nil {
		return
	}

	// Read username
	username := make([]byte, ulen[0])
	if _, err = io.ReadFull(mc, username); err != nil {
		return
	}

	// Read password length
	plen := make([]byte, 1)
	if _, err = io.ReadFull(mc, plen); err != nil {
		return
	}

	// Read password
	password := make([]byte, plen[0])
	if _, err = io.ReadFull(mc, password); err != nil {
		return
	}
	user.Username = string(username)
	user.Password = string(password)
	return
}

// SendAuthStatus sends username/password authentication status
func (mc *MethodSelection) SendAuthStatus(status byte) error {
	resp := []byte{AUTH_VERSION, status}
	_, err := mc.Write(resp)
	return err
}

// SendAuthResponse sends authentication method selection response
func (mc *MethodSelection) AcceptMethod(method byte) error {
	resp := []byte{SOCKS5, method}
	_, err := mc.Write(resp)
	return err
}

// PacketConn wraps both connection and packet information
type PacketConn struct {
	net.Conn
	version  byte
	command  byte
	reserved byte
	addrType byte
	address  string
	port     uint16
}

// NewPacketConn creates a new PacketConn from an existing connection
func NewPacketConn(conn net.Conn) (*PacketConn, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != SOCKS5 {
		return nil, fmt.Errorf("unsupported protocol version: %v", header[0])
	}

	pc := &PacketConn{
		Conn:     conn,
		version:  header[0],
		command:  header[1],
		reserved: header[2],
		addrType: header[3],
	}

	// Read address
	switch pc.addrType {
	case IPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		pc.address = net.IP(addr).String()
	case DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return nil, err
		}
		length := int(lenByte[0])

		domain := make([]byte, length)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		pc.address = string(domain)
	case IPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		pc.address = net.IP(addr).String()

	default:
		return nil, errors.New("unsupported address type")
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, err
	}
	pc.port = binary.BigEndian.Uint16(portBytes)

	return pc, nil
}

// Address returns the full address (host:port) as string
func (pc *PacketConn) Address() string {
	return net.JoinHostPort(pc.address, strconv.Itoa(int(pc.port)))
}

// Command returns the SOCKS command
func (pc *PacketConn) Command() byte {
	return pc.command
}

// AddressType returns the address type
func (pc *PacketConn) AddressType() byte {
	return pc.addrType
}

// SendResponse sends a SOCKS5 response with the given status
func (pc *PacketConn) SendStatus(status byte) error {
	resp := []byte{
		SOCKS5,     // Version
		status,     // Status
		0x00,       // Reserved
		IPv4,       // Address type (IPv4)
		0, 0, 0, 0, // IP address (0.0.0.0)
		0, 0, // Port (0)
	}
	_, err := pc.Write(resp)
	return err
}

// Copy copies data between the packet connection and destination
func (pc *PacketConn) Copy(dest net.Conn) error {
	// Start proxying data
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(dest, pc)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(pc, dest)
		errCh <- err
	}()

	// Wait for any error or EOF
	return <-errCh
}
