package asusctl

import (
	"os/exec"
	"syscall"
)

func detachCoreWorker(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
