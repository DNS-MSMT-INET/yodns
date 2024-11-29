package cmd

import (
	"encoding/json"
	"fmt"
	"testing"
)

func Test_Key(t *testing.T) {
	t.Skipf("skipping test")

	var objmap map[string]json.RawMessage
	err := json.Unmarshal([]byte("{ \"k\": 1, \"k2\": \"hello\" }"), &objmap)
	if err != nil {
		t.Errorf("Error unmarshalling: %v", err)
	}

	var key any
	err = json.Unmarshal(objmap["k2"], &key)
	if err != nil {
		t.Errorf("Error unmarshalling: %v", err)
	}

	fmt.Println(fmt.Sprintf("%v", key))
}

func Test_CanAppendToBucket(t *testing.T) {
	t.Skipf("skipping test")

	writer, closeFunc, err := getFileWriter("test.zst", true)
	if err != nil {
		t.Error(err)
		return
	}

	writer.Write([]byte("firstline\n"))
	writer.Write([]byte("secondline\n"))
	closeFunc()

	writer, closeFunc, err = getFileWriterAppend("test.zst", true)
	if err != nil {
		t.Error(err)
		return
	}
	writer.Write([]byte("thidline\n"))
	writer.Write([]byte("fourthline\n"))
	closeFunc()
}

func Test_DedupMap(t *testing.T) {

	dedupMap := NewSyncMapCapacity[string, any](2)

	fmt.Println(dedupMap.LoadOrStore("1", nil))
	fmt.Println(dedupMap.LoadOrStore("1", nil))
	fmt.Println(dedupMap.LoadOrStore("2", nil))
	fmt.Println(dedupMap.LoadOrStore("3", nil))
	fmt.Println(dedupMap.LoadOrStore("1", nil))
}
