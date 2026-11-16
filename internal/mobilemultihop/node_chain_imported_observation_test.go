package mobilemultihop

import (
	"fmt"
	"testing"
)

func TestImportedSourceObservationKeepsOriginalReceipt(t *testing.T) {
	for _, prefixes := range []int{1, 6} {
		for _, fault := range []string{"original", "copied-receipt", "foreign-receipt", "resealed-source", "changed-receipt", "middle-input", "copied-middle", "copied-prefix", "count", "nil-receipt"} {
			t.Run(fmt.Sprintf("%d/%s", prefixes+2, fault), func(t *testing.T) {
				source := nodeChainImportedSSPrefixFixture(t, prefixes, "wg", "2022-blake3-aes-256-gcm", false)
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "copied-receipt":
					copy := *chain.importedOwners
					chain.importedOwners = &copy
				case "foreign-receipt":
					other, e := NewNodeChain(startJSON(t, source))
					if e != nil {
						t.Fatal(e)
					}
					chain.importedOwners = other.importedOwners
				case "resealed-source":
					chain.sourceJSON += " "
					chain.seal = chain.captureSeal()
				case "changed-receipt":
					chain.importedOwners.sourceJSON += " "
				case "middle-input":
					chain.importedMiddle.input += " "
				case "copied-middle":
					copy := *chain.importedMiddle
					chain.importedMiddle = &copy
				case "copied-prefix":
					copy := *chain.nodes[0]
					chain.nodes[0] = &copy
				case "count":
					chain.importedOwners.count--
				case "nil-receipt":
					chain.importedOwners = nil
				}
				err = chain.validateCapture()
				if fault != "original" {
					if err == nil {
						t.Fatal("imported observation accepted changed original receipt", fault)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, target := range []string{"linux", "windows", "darwin", "android", "ios"} {
					projected, e := ProjectNodeChain(chain, target, 0)
					if e != nil {
						t.Fatal(e)
					}
					if projected == chain || projected.importedOwners == chain.importedOwners || projected.importedOwners.owner != projected || projected.validateCapture() != nil {
						t.Fatal("authorized projection lost fresh original receipt", target)
					}
				}
			})
		}
	}
}
