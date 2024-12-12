// main.go
package main

import (
	"io"
	"log"

	"github.com/lsongdev/socks-go/socks"
)

type MyHandler struct {
	socks.DefaultServerHandler

	client *socks.Client
}

func (h *MyHandler) HandleAuth(user *socks.User) error {
	log.Println("User", user)
	return nil
}

func (h *MyHandler) HandleRequest(conn *socks.PacketConn) {
	log.Println("-->", conn.Address())
	dest, err := h.client.Dial("tcp", conn.Address())
	if err != nil {
		log.Printf("Failed to connect to %s: %v", conn.Address(), err)
		conn.SendStatus(socks.HOST_UNREACHABLE) // Host unreachable
		return
	}
	defer dest.Close()
	// Send success response
	if err := conn.SendStatus(socks.SUCCESS); err != nil {
		log.Printf("Failed to send response: %v", err)
		return
	}
	// Start proxying data
	go func() {
		defer conn.Close()
		defer dest.Close()
		io.Copy(dest, conn)
	}()
	io.Copy(conn, dest)
}

func main() {

	client := socks.NewClient(&socks.ClientConfig{
		Host: "example.com",
		Port: 1080,
		User: &socks.User{
			Username: "username",
			Password: "password",
		},
	})

	h := &MyHandler{
		client: client,
	}
	server := socks.NewServer()
	log.Printf("Starting SOCKS5 server on :1080")
	if err := server.ListenAndServe(":1080", h); err != nil {
		log.Fatal(err)
	}
}
