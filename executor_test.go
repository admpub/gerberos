package gerberos

import (
	"strings"
	"testing"
)

func TestExecutorDefaultExecute(t *testing.T) {
	e := &defaultExecutor{}
	ts := "test"
	o, c, err := e.Execute("echo", ts)
	testNoError(t, err)
	o = strings.TrimSuffix(o, "\n")
	if o != ts {
		t.Errorf(`expected output "%s", got "%s"`, ts, o)
	}
	if c != 0 {
		t.Errorf(`expected exit code 0, got %d`, c)
	}
}

func TestExecutorDefaultExitError(t *testing.T) {
	e := &defaultExecutor{}
	_, c, err := e.Execute("cat", "--invalid-flag")
	testError(t, err)
	if c != 1 {
		t.Errorf(`expected exit code 1, got %d`, c)
	}
}

func TestExecutorDefaultUnknownCommandFlaky(t *testing.T) {
	e := &defaultExecutor{}
	_, c, err := e.Execute("unknown_command_baighah6othoo0ikei9Ahngay2geifah")
	testError(t, err)
	if c != -1 {
		t.Errorf(`expected exit code -1, got %d`, c)
	}
}
