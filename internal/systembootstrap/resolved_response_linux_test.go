//go:build linux

package systembootstrap

import "testing"

func TestResolvedResponseScopeWinner(t *testing.T) {
	question, err := queryFor("vpn.example", 1, false, false)
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte(nil), question...)
	base[2] = 0x81
	base[3] = 0x80
	for _, name := range []string{"address", "no-data", "negative", "wrong-id", "truncated", "alias-cycle"} {
		t.Run(name, func(t *testing.T) {
			response := append([]byte(nil), base...)
			success, wantErr := true, false
			switch name {
			case "address":
				response[7] = 1
				response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
			case "negative":
				response[3] |= 3
				success = false
			case "wrong-id":
				response[0] ^= 1
				wantErr = true
			case "truncated":
				response[2] |= 2
				wantErr = true
			case "alias-cycle":
				response[7] = 1
				response = append(response, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12)
				wantErr = true
			}
			got, e := ResolvedResponseSuccess(question, response)
			if (e != nil) != wantErr || !wantErr && got != success {
				t.Fatalf("winner=%v error=%v", got, e)
			}
		})
	}
}
