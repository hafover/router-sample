package utils

import (
	"os"
	"strconv"
	"syscall"
)

type PidFile struct {
	Name string
	file *os.File
}

func (p *PidFile) Lock() (err error) {
	if p.file, err = os.OpenFile(p.Name, os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		return
	}
	if err = syscall.Flock(int(p.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return
	}
	if err = p.file.Truncate(0); err != nil {
		return
	}
	if _, err = p.file.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		return
	}
	return
}

func (p *PidFile) Unlock() {
	_ = syscall.Flock(int(p.file.Fd()), syscall.LOCK_UN)
	p.file.Close()
	_ = os.Remove(p.Name)
}
