package protobuf

import (
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"testing"
)

// TestReader_CanReadLegacyFileFormat tests if the reader can read the legacy file format
// that uses 16 byte UUIDs instead of snowflake IDs.
func TestReader_CanReadLegacyFileFormat(t *testing.T) {
	zip := serialization.ZipZSTD
	r, _ := NewFileReader("testdata/example.com.commit=d8c45a9.pb.zst")
	r.Zip = &zip

	out := make(chan resolver.Result)
	go func() {
		if err := r.ReadTo(out); err != nil {
			panic(err)
		}
	}()

	for result := range out {
		if len(result.Domains) == 0 {
			t.Errorf("Expected the file to contain 'example.org.', found empty array")
		}

		if !result.Domains[0].Name.EqualString("example.com.") {
			t.Errorf("Expected the file to contain 'example.org.', found %v", result.Domains[0].Name)
		}
	}
}

// TestReader_CanReadLegacyFileFormat tests if the reader can read the file format of the published data
// that uses 4 byte short UUIDs and 16 byte long UUIDs (when the 4 byte UUIDs is not unique.)
func TestReader_CanReadPublishedFileFormat(t *testing.T) {
	zip := serialization.ZipZSTD
	r, _ := NewFileReader("testdata/example.com.commit=d8c45a9.pb.zst")
	r.Zip = &zip

	out := make(chan resolver.Result)
	go func() {
		if err := r.ReadTo(out); err != nil {
			panic(err)
		}
	}()

	for result := range out {
		if len(result.Domains) == 0 {
			t.Errorf("Expected the file to contain 'example.org.', found empty array")
		}

		if !result.Domains[0].Name.EqualString("example.com.") {
			t.Errorf("Expected the file to contain 'example.org.', found %v", result.Domains[0].Name)
		}
	}
}
