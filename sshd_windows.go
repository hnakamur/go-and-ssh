// +build windows

package sshd

import (
	"io"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

type ShellFile struct {
	reader io.ReadCloser
	writer io.WriteCloser
	cmd    *exec.Cmd
}

func (s *Server) startShell(shellPath string, connection ssh.Channel) *ShellFile {
	shell := exec.Command(shellPath)

	// TODO On Windows, shell not echo back.
	writer, err := shell.StdinPipe()
	if err != nil {
		s.logger.Printf("Could not start pty (%s)", err)
		return nil
	}
	reader, err := shell.StdoutPipe()
	if err != nil {
		s.logger.Printf("Could not start pty (%s)", err)
		return nil
	}
	err = shell.Start()
	if err != nil {
		s.logger.Printf("Could not start pty (%s)", err)
		return nil
	}
	//pipe session to shell and visa-versa
	go func() {
		io.Copy(connection, reader)
		reader.Close()
	}()
	go func() {
		io.Copy(writer, connection)
		writer.Close()
	}()
	return &ShellFile{reader: reader, writer: writer, cmd: shell}
}

func (sf *ShellFile) setWinsize(w, h uint32) {
	// TODO
}
