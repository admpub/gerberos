package gerberos

import (
	"errors"
	"fmt"
	"os"
)

type source interface {
	initialize(r *Rule) error
	matches() (chan *match, error)
}

type fileSource struct {
	Rule *Rule
	path string
}

func (s *fileSource) initialize(r *Rule) error {
	s.Rule = r

	if len(r.Source) < 2 {
		return errors.New("missing path parameter")
	}
	s.path = r.Source[1]

	if fi, err := os.Stat(s.path); err == nil && fi.IsDir() {
		return fmt.Errorf(`"%s" is a directory`, s.path)
	}

	if len(r.Source) > 2 {
		return errors.New("superfluous parameter(s)")
	}

	return nil
}

func (s *fileSource) matches() (chan *match, error) {
	return s.Rule.processScanner("tail", "-n", "0", "-F", s.path)
}

type systemdSource struct {
	Rule    *Rule
	service string
}

func (s *systemdSource) initialize(r *Rule) error {
	s.Rule = r

	if len(r.Source) < 2 {
		return errors.New("missing service parameter")
	}
	s.service = r.Source[1]

	if len(r.Source) > 2 {
		return errors.New("superfluous parameter(s)")
	}

	return nil
}

func (s *systemdSource) matches() (chan *match, error) {
	return s.Rule.processScanner("journalctl", "-n", "0", "-f", "-u", s.service)
}

type kernelSource struct {
	Rule *Rule
}

func (k *kernelSource) initialize(r *Rule) error {
	k.Rule = r

	if len(r.Source) > 1 {
		return errors.New("superfluous parameter(s)")
	}

	return nil
}

func (k *kernelSource) matches() (chan *match, error) {
	return k.Rule.processScanner("journalctl", "-kf", "-n", "0")
}

type testSource struct {
	Rule        *Rule
	matchesErr  error
	processPath string
}

func (s *testSource) initialize(r *Rule) error {
	s.Rule = r

	return nil
}

func (s *testSource) matches() (chan *match, error) {
	if s.matchesErr != nil {
		return nil, s.matchesErr
	}

	p := "test/producer"
	if s.processPath != "" {
		p = s.processPath
	}
	return s.Rule.processScanner(p)
}

type processSource struct {
	Rule *Rule
	name string
	args []string
}

func (s *processSource) initialize(r *Rule) error {
	s.Rule = r

	if len(r.Source) < 2 {
		return errors.New("missing process name")
	}
	s.name = r.Source[1]

	s.args = r.Source[2:]

	return nil
}

func (s *processSource) matches() (chan *match, error) {
	return s.Rule.processScanner(s.name, s.args...)
}
