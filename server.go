// Package sshd provides a subset of the ssh server protocol.
// Only supported request types are exec, shell, pty-req, and window-change.
package sshd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// Server is the sshd server.
type Server struct {
	shellPath string
	config    *ssh.ServerConfig
	logger    *log.Logger
	listener  net.Listener

	mu     sync.Mutex
	closed bool
}

// NewServer creates a sshd server.
// The shellPath is the path of the shell (e.g., "bash").
// You can pass nil as logger if you want to disable log outputs.
func NewServer(shellPath string, config *ssh.ServerConfig, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	return &Server{shellPath: shellPath, config: config, logger: logger}
}

// ListenAndServe let the server listen and serve.
func (s *Server) ListenAndServe(addr string) error {
	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Failed to listen on %s (%s)", addr, err)
	}
	return s.Serve(listener)
}

// Serve let the server accept incoming connections and handle them.
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	for {
		tcpConn, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return fmt.Errorf("Failed to accept incoming connection (%s)", err)
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		_, chans, reqs, err := ssh.NewServerConn(tcpConn, s.config)
		if err != nil {
			return err
		}

		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go s.handleChannels(chans)
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *Server) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *Server) handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		s.logger.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		var shellf *ShellFile

		for req := range requests {
			//fmt.Printf("req=%+v\n", req)
			switch req.Type {
			case "exec":
				req.Reply(true, nil)

				cmd := parseCommand(req.Payload)
				var shell *exec.Cmd
				if runtime.GOOS == "windows" {
					shell = exec.Command("cmd", "/c", cmd)
				} else {
					shell = exec.Command(s.shellPath, "-c", cmd)
				}

				var err error
				var in io.WriteCloser
				var out io.ReadCloser

				// Prepare teardown function
				close := func() {
					in.Close()

					err := shell.Wait()
					var exitStatus int32
					if err != nil {
						if e2, ok := err.(*exec.ExitError); ok {
							if s, ok := e2.Sys().(syscall.WaitStatus); ok {
								exitStatus = int32(s.ExitStatus())
							} else {
								panic(errors.New("Unimplemented for system where exec.ExitError.Sys() is not syscall.WaitStatus."))
							}
						}
					}
					var b bytes.Buffer
					binary.Write(&b, binary.BigEndian, exitStatus)
					connection.SendRequest("exit-status", false, b.Bytes())
					connection.Close()
					s.logger.Printf("Session closed")
				}

				in, err = shell.StdinPipe()
				if err != nil {
					s.logger.Printf("Could not get stdin pipe (%s)", err)
					close()
					return
				}

				out, err = shell.StdoutPipe()
				if err != nil {
					s.logger.Printf("Could not get stdout pipe (%s)", err)
					close()
					return
				}

				err = shell.Start()
				if err != nil {
					s.logger.Printf("Could not start pty (%s)", err)
					close()
					return
				}

				//pipe session to shell and visa-versa
				var once sync.Once
				go func() {
					io.Copy(connection, out)
					once.Do(close)
				}()
				go func() {
					io.Copy(in, connection)
					once.Do(close)
				}()
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)

					// Fire up bash for this session
					shellf = s.startShell(s.shellPath, connection)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				shellf.setWinsize(w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				shellf.setWinsize(w, h)
			}
		}
	}()
}

func parseCommand(b []byte) string {
	l := int(binary.BigEndian.Uint32(b))
	cmd := string(b[4:])
	if len(cmd) != l {
		log.Fatalf("command length unmatch, got=%d, want=%d", len(cmd), l)
	}
	return cmd
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
