package filetrust

import (
	"strings"
	"testing"
)

const (
	aceAllow       = 0x00
	aceDeny        = 0x01
	aceAllowObject = 0x05
)

var daclTrusted = map[string]bool{
	SystemSID:             true,
	AdministratorsSID:     true,
	"S-1-5-21-1-2-3-1001": true,
}

func TestTrustedDACLViolation(t *testing.T) {
	const (
		usersSID   = "S-1-5-32-545"
		fileRead   = 0x0001
		fileWrite  = 0x0002
		genericAll = 0x10000000
	)
	write := TrustOptions{DenyForeignWrite: true}
	read := TrustOptions{DenyForeignRead: true}
	tests := []struct {
		name    string
		null    bool
		aces    []daclACE
		opts    TrustOptions
		wantErr string
	}{
		{name: "no policy accepts anything", aces: []daclACE{{SID: usersSID, Mask: genericAll, Type: aceAllow}}},
		{name: "trusted principals may write", opts: write, aces: []daclACE{
			{SID: SystemSID, Mask: genericAll, Type: aceAllow},
			{SID: AdministratorsSID, Mask: genericAll, Type: aceAllow},
			{SID: "S-1-5-21-1-2-3-1001", Mask: genericAll, Type: aceAllow},
		}},
		{name: "foreign read is fine for the targets rule", opts: write, aces: []daclACE{
			{SID: usersSID, Mask: fileRead, Type: aceAllow},
		}},
		{name: "foreign write is refused", opts: write, aces: []daclACE{
			{SID: usersSID, Mask: fileWrite, Type: aceAllow},
		}, wantErr: "write"},
		{name: "generic all is refused for read", opts: read, aces: []daclACE{
			{SID: usersSID, Mask: genericAll, Type: aceAllow},
		}, wantErr: "read"},
		{name: "foreign read refused for the key", opts: read, aces: []daclACE{
			{SID: usersSID, Mask: fileRead, Type: aceAllow},
		}, wantErr: "read"},
		{name: "deny ACEs do not grant", opts: read, aces: []daclACE{
			{SID: usersSID, Mask: fileRead, Type: aceDeny},
		}},
		{name: "unattributable allow ACE fails closed", opts: read, aces: []daclACE{
			{SID: "", Mask: fileRead, Type: aceAllowObject},
		}, wantErr: "unrecognised principal"},
		{name: "NULL DACL fails closed", null: true, opts: write, wantErr: "no DACL"},
		{name: "no ACEs is fine", opts: write},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := trustedDACLViolation(tc.null, tc.aces, daclTrusted, tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected violation: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a violation, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestTrustedDACLViolation_ExtendedGrantACETypes(t *testing.T) {
	const (
		fileRead         = 0x0001
		aceAllowCompound = 0x04
		aceAllowCallback = 0x09
		aceAllowCbObject = 0x0B
		aceUnknown       = 0x7F
		aceAudit         = 0x02
		aceDenyCallback  = 0x0A
		aceMandatoryLbl  = 0x11
	)
	read := TrustOptions{DenyForeignRead: true}
	for _, tc := range []struct {
		name    string
		aceType uint8
		wantErr bool
	}{
		{"compound allow fails closed", aceAllowCompound, true},
		{"callback conditional allow fails closed", aceAllowCallback, true},
		{"callback object allow fails closed", aceAllowCbObject, true},
		{"unknown ACE type fails closed", aceUnknown, true},
		{"system audit ignored", aceAudit, false},
		{"callback deny ignored", aceDenyCallback, false},
		{"mandatory label ignored", aceMandatoryLbl, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := trustedDACLViolation(false, []daclACE{{SID: "", Mask: fileRead, Type: tc.aceType}}, daclTrusted, read)
			if (err != nil) != tc.wantErr {
				t.Fatalf("aceType=%#x err=%v, wantErr=%v", tc.aceType, err, tc.wantErr)
			}
		})
	}
}
