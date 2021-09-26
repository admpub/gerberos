package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestNFTRuleSetIPsInSet(t *testing.T) {
	j := `{"nftables": [{"set": {"name": "gerberos4", "table": "gerberos4", "elem": [{"elem": {"val": "1.2.3.4"}}, {"elem": {"val": "2.3.4.5"}}]}}]}`
	nrs := &nftRuleSet{}
	if err := nrs.decode(strings.NewReader(j)); err != nil {
		t.Fail()
	}
	if len(nrs.ipsInSet("gerberos5", "gerberos4")) > 0 {
		t.Fail()
	}
	if len(nrs.ipsInSet("gerberos4", "gerberos5")) > 0 {
		t.Fail()
	}
	if len(nrs.ipsInSet("gerberos4", "")) > 0 {
		t.Fail()
	}
	if len(nrs.ipsInSet("", "")) > 0 {
		t.Fail()
	}
	if !reflect.DeepEqual(nrs.ipsInSet("gerberos4", "gerberos4"), []string{"1.2.3.4", "2.3.4.5"}) {
		t.Fail()
	}
}
