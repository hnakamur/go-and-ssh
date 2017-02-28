// +build !windows

package sshd

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/ssh"

	"github.com/kr/pty"
)

type ShellFile struct {
	file *os.File
}

// start shell
func (s *Server) startShell(shellPath string, connection ssh.Channel) *ShellFile {
	shell := exec.Command(shellPath)

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := shell.Process.Wait()
		if err != nil {
			s.logger.Printf("Failed to exit shell (%s)", err)
		}
		s.logger.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	s.logger.Print("Creating pty...")
	file, err := pty.Start(shell)
	if err != nil {
		s.logger.Printf("Could not start pty (%s)", err)
		close()
		return nil
	}

	//pipe session to shell and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, file)
		once.Do(close)
	}()
	go func() {
		io.Copy(file, connection)
		once.Do(close)
	}()
	return &ShellFile{file}
}

// SetWinsize sets the size of the given pty.
func (sf *ShellFile) setWinsize(w, h uint32) {
	fd := sf.file.Fd()
	ws := &winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
