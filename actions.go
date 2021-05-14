package main

import (
	"errors"
	"fmt"
	"log"
	"time"
)

type action interface {
	initialize(*rule) error
	perform(*match) error
}

type banAction struct {
	rule     *rule
	duration time.Duration
}

func (a *banAction) initialize(r *rule) error {
	a.rule = r

	if len(r.Action) < 2 {
		return errors.New("missing duration parameter")
	}

	d, err := time.ParseDuration(r.Action[1])
	if err != nil {
		return fmt.Errorf("failed to parse duration parameter: %s", err)
	}
	a.duration = d

	if len(r.Action) > 2 {
		return errors.New("superfluous parameter(s)")
	}

	return nil
}

func (a *banAction) perform(m *match) error {
	return backend.Ban(a.rule, m.ip, m.ipv6, a.duration)
}

type logAction struct {
	rule     *rule
	extended bool
}

func (a *logAction) initialize(r *rule) error {
	a.rule = r

	if len(r.Action) < 2 {
		return errors.New("missing level parameter")
	}

	switch r.Action[1] {
	case "simple":
		a.extended = false
	case "extended":
		a.extended = true
	default:
		return errors.New("invalid level parameter")
	}

	if len(r.Action) > 2 {
		return errors.New("superfluous parameter(s)")
	}

	return nil
}

func (a *logAction) perform(m *match) error {
	var s string
	if a.extended {
		s = m.stringExtended()
	} else {
		s = m.stringSimple()
	}
	log.Printf("%s: %s", a.rule.name, s)

	return nil
}
