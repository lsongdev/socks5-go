package socks

import (
	"log"
	"net"
)

type ServerHandler interface {
	HandleAuth(user *User) error
	HandleRequest(conn *PacketConn)
}

type Server struct {
	AllowMethods []byte
}

func NewServer() *Server {
	return &Server{
		AllowMethods: []byte{USERNAME_AUTH, NO_AUTH},
	}
}

func (s *Server) ListenAndServe(addr string, handler ServerHandler) error {
	if handler == nil {
		handler = &DefaultServerHandler{}
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go s.handleConnection(conn, handler)
	}
}

func (s *Server) selectMethod(methods []byte) byte {
	// Check if any of the client's methods match our supported methods
	for _, serverMethod := range s.AllowMethods {
		for _, clientMethod := range methods {
			if clientMethod == serverMethod {
				return clientMethod
			}
		}
	}
	return NO_ACCEPT_METHODS
}

func (s *Server) handleConnection(conn net.Conn, h ServerHandler) {
	defer conn.Close()
	// Parse client's method selection message
	mc, err := ParseMethodSelection(conn)
	if err != nil {
		log.Printf("Failed to parse methods: %v", err)
		return
	}
	// Let handler choose the authentication method
	method := s.selectMethod(mc.Methods)
	if err := mc.AcceptMethod(method); err != nil {
		log.Printf("Failed to send auth response: %v", err)
		return
	}

	if method == NO_ACCEPT_METHODS {
		return
	}

	// Handle authentication based on selected method
	if method == USERNAME_AUTH {
		user, err := mc.ReadUser()
		if err != nil {
			log.Printf("Failed to read auth packet: %v", err)
			return
		}
		err = h.HandleAuth(&user)
		if err != nil {
			mc.SendAuthStatus(FAILURE) // Authentication failed
			log.Printf("Authentication failed: %v", err)
			return
		}
		mc.SendAuthStatus(SUCCESS) // Authentication successful
	}

	// Parse and handle the request
	pc, err := NewPacketConn(conn)
	if err != nil {
		log.Printf("Failed to parse request: %v", err)
		return
	}
	h.HandleRequest(pc)
}

type DefaultServerHandler struct {
}

func (h *DefaultServerHandler) HandleAuth(user *User) error {
	// Default handler rejects all auth attempts
	// return false, errors.New("authentication not supported in default handler")
	return nil
}

func (h *DefaultServerHandler) HandleRequest(conn *PacketConn) {
	target := conn.Address()
	dest, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		conn.SendStatus(HOST_UNREACHABLE)
		return
	}
	defer dest.Close()

	if err := conn.SendStatus(SUCCESS); err != nil {
		log.Printf("Failed to send response: %v", err)
		return
	}

	if err := conn.Copy(dest); err != nil {
		log.Printf("Connection copy error: %v", err)
	}
}
