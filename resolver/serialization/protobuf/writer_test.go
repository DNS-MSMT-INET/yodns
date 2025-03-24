package protobuf

import (
	"bytes"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/godruoyi/go-snowflake"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path"
	"sync"
	"testing"
	"time"
)

func TestProto_WriteAndRead_Single(t *testing.T) {
	t.Skipf("only for benchmarking")
	testProtoWriteAndRead(t, 1)
}

func TestProto_WriteAndRead_Multiple(t *testing.T) {
	t.Skipf("only for benchmarking")
	testProtoWriteAndRead(t, 5)
}

func TestProto_Load(t *testing.T) {
	t.Skipf("only for benchmarking")

	dir := "C:/Users/fsteurer.LAP-21-0158/Documents/dnsmonitor/experiments/data/tranco/2023-09-05-13-47_77394f6/scan"
	input := path.Join(dir, "output_623_99dab87b.pb.zst")

	var readErr error
	var writeErr error
	i := 0
	for readErr == nil && writeErr == nil {
		readChan := make(chan resolver.Result)
		reader, _ := NewFileReader(input)
		go func() {
			readErr = reader.ReadTo(readChan)
		}()

		writer := NewWriter(dir, fmt.Sprintf("test_output_%v", i), 100, serialization.ZipDefault, serialization.CompressionFast, 1)
		input = path.Join(dir, fmt.Sprintf("test_output_%v_0_.pb.zst", i))
		i++
		writer.RandomFileSuffix = ""

		for r := range readChan {
			fmt.Println(r.Domains)
			//writeErr = writer.WriteAsync(r)
		}

		writeErr = writer.Wait()
	}

	if readErr != nil {
		t.Errorf("read error: %v", readErr)
	}

	if writeErr != nil {
		t.Errorf("write error: %v", writeErr)
	}

}

// TestProto_CanReadWrite_LargeResult tests whether we can read and write a large result message (> 4GB, 2^32 bytes)
// Protobuf is not made for very large messages...
// Unfortunately, we can sometimes reach the limit.
// https://stackoverflow.com/questions/34128872/google-protobuf-maximum-size
func TestProto_CanReadWrite_LargeResult(t *testing.T) {
	t.Skipf("only for benchmarking")

	generateMessages := func(n int) *model.MsgIdx {
		result := model.NewMessageIdx()
		for i := 0; i < n; i++ {
			result.AppendMessage(model.MessageExchange{
				OriginalQuestion: model.Question{
					Name:  model.MustNewDomainName(fmt.Sprintf("ns%v.example.com.", i)),
					Type:  2,
					Class: 1,
				},
				Message: &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id: 4321,
					},
					Question: getQuestion(),
					Answer:   getManyResourceRecords(100),
					Ns:       getManyResourceRecords(100),
					Extra:    getManyResourceRecords(100),
				},
			})
		}
		return result
	}

	write := resolver.Result{
		Domains: []resolver.TaggedDomainName{{
			Name: model.MustNewDomainName("superlarge.example.com."),
		}},
		StartTime: time.Now(),
		Duration:  time.Minute,
		Zone: &model.Zone{
			Name: model.MustNewDomainName("superlarge.example.com."),
			NameServers: []*model.NameServer{{
				Name:        "ns1.example.com.",
				IPAddresses: common.NewCompSet(netip.MustParseAddr("198.51.100.1")),
			}},
		},
		Msgs: generateMessages(500000),
	}

	writer := NewWriter("", "test", 1, serialization.ZipDefault, serialization.CompressionFast, 1)
	fileName := fmt.Sprintf("test_0_%v.pb", writer.RandomFileSuffix)
	defer func() {
		if _, err := os.Stat(fileName); err == nil {
			_ = os.Remove(fileName)
		}
	}()

	if err := writer.WriteAsync(write); err != nil {
		t.Error(err)
		t.FailNow()
	}

	if err := writer.Wait(); err != nil {
		t.Error(err)
		t.FailNow()
	}

	if stat, err := os.Stat(fileName); err != nil || stat.Size() < math.MaxUint32 {
		t.Errorf("File not created or smaller than 4GB: %v", err)
	}

	readChan := make(chan resolver.Result)
	reader, _ := NewFileReader(fileName)
	go func() {
		if err := reader.ReadTo(readChan); err != nil {
			t.Error(err)
		}

	}()

	resultWasRead := false
	for read := range readChan {
		resultWasRead = true
		if slices.Equal(read.Domains, write.Domains) {
			t.Errorf("expected domain name %v, got %v", read.Domains, write.Domains)
		}
		if read.Msgs.Count() != write.Msgs.Count() {
			t.Errorf("expected %v name servers, got %v", write.Msgs.Count(), read.Msgs.Count())
		}
	}

	if !resultWasRead {
		t.Errorf("no results read")
	}

}

// TODO
// Test - WriteAsync fails early
// Test - Wait can return error
// Test - Can quit gracefully

// TestProto_Benchmark_Zip reads an output folder with the tools output (preferably some GB of data)
// and writes them back with compression
func TestProto_Benchmark_Zip(t *testing.T) {
	t.Skipf("only for benchmarking")

	input := "<enterpath>/output_*.pb"
	output := "<enterpath>/rezipped"
	outputFileSize := uint(100)
	entriesToRead := 10000
	writeWorkers := 10

	readChan := make(chan resolver.Result)
	reader, _ := NewFileReader(input)

	go reader.ReadTo(readChan)

	// Read everything into memory,
	// so the reading does not interfere with the writing
	i := 0
	results := make(chan resolver.Result, entriesToRead)
	for result := range readChan {
		results <- result
		if i > entriesToRead {
			break
		}
		i++
	}
	close(results)

	writer := Writer{
		FileWriterBase: serialization.NewFileWriterBase(output, "output", "pb", outputFileSize, 5, false, serialization.ZipDeflate, serialization.CompressionFast),
	}

	start := time.Now()

	var writeWorkersWg sync.WaitGroup
	writeWorkersWg.Add(writeWorkers)
	for i := 0; i < writeWorkers; i++ {
		go func() {
			for result := range results {
				writer.WriteAsync(result)
			}
			writeWorkersWg.Done()
		}()
	}

	writeWorkersWg.Wait()
	writer.Wait()

	fmt.Printf("Took %v\n", time.Since(start))
}

func testProtoWriteAndRead(t *testing.T, n int) {
	// Tweak the writer creation, so we can do it in memory
	var bytesBuffer = new(bytes.Buffer)
	serialization.InnerWriterFactory = func(filePath string, zipAlgorithm serialization.ZipAlgorithm, compression serialization.CompressionLevel) (io.Writer, func() error, error) {
		return bytesBuffer, func() error { return nil }, nil
	}

	writer := NewWriter("outDir", "prefix", 1, serialization.ZipNone, serialization.CompressionFast, 1)
	resultChan := make(chan resolver.Result, n)
	var writeResults []resolver.Result
	for i := 0; i < n; i++ {
		writeResults = append(writeResults, getExampleResolverResult())
	}

	// Serialize
	for _, writeResult := range writeResults {
		if err := writer.WriteAsync(writeResult); err != nil {
			t.Fatalf("error writing: %v", err)
		}
		timeout := time.AfterFunc(time.Second, func() {
			t.Fatalf("timeout serializing result")
		})
		timeout.Stop()
	}

	if err := writer.Wait(); err != nil {
		t.Fatalf("error waiting for writer: %v", err)
	}

	// Deserialize
	totalBytesWritten := bytesBuffer.Bytes()
	if len(totalBytesWritten) == 0 {
		t.Fatalf("no bytes written")
	}

	ioReader := bytes.NewReader(totalBytesWritten)
	go ReadAllMessages(common.Background(), ioReader,
		func(exchange *MessageExchange) (model.MessageExchange, error) {
			return exchange.ToModel()
		}, resultChan)

	for i := 0; i < n; i++ {
		timeout := time.AfterFunc(time.Second, func() {
			t.Fatalf("timeout reading results back")
		})
		readBackResult := <-resultChan
		timeout.Stop()

		// Assert
		if !writeResults[i].StartTime.Equal(readBackResult.StartTime) {
			t.Errorf("written and read-back 'StartTime' does not match")
		}
		if writeResults[i].Duration != readBackResult.Duration {
			t.Errorf("written and read-back 'Duration' does not match")
		}
		if slices.Equal(writeResults[i].Domains, readBackResult.Domains) {
			t.Errorf("written and read-back 'Domain' does not match")
		}
		// Write better assertions than below...they always fail because of order and pointer differences
		//if !reflect.DeepEqual(writeResults[i].Msgs, readBackResult.Msgs) {
		//	t.Errorf("written and read-back 'Msgs' do not match")
		//}
		//if !reflect.DeepEqual(writeResults[i].Zone, readBackResult.Zone) {
		//	t.Errorf("written and read-back 'Zones' do not match")
		//}
	}
}

func getExampleResolverResult() resolver.Result {
	domainName := fmt.Sprintf("%v.example.com.", uuid.New().String())

	msgs := model.NewMessageIdx()
	msgs.AppendMessage(model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  ".",
			Type:  2,
			Class: 1,
		},
		NameServerIP: netip.MustParseAddr("2001:db8::1"),
		Metadata: model.Metadata{
			FromCache:     false,
			RetryIdx:      0,
			ConnId:        snowflake.ID(),
			TCP:           false,
			CorrelationId: snowflake.ID(),
			ParentId:      snowflake.ID(),
			EnqueueTime:   time.Now(),
			DequeueTime:   time.Now(),
		},
		Error: &model.SendError{
			Message: "This is an error",
		},
	})

	msgs.AppendMessage(model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  "com.",
			Type:  2,
			Class: 1,
		},
		ResponseAddr: "2001:db8::1",
		NameServerIP: netip.MustParseAddr("2001:db8::1"),
		Metadata: model.Metadata{
			FromCache:     true,
			RetryIdx:      4,
			ConnId:        snowflake.ID(),
			TCP:           true,
			CorrelationId: snowflake.ID(),
			ParentId:      snowflake.ID(),
			EnqueueTime:   time.Now(),
			DequeueTime:   time.Now(),
		},
		Message: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 1234,
				Response:           true,
				Opcode:             0,
				Authoritative:      true,
				Truncated:          true,
				RecursionDesired:   true,
				RecursionAvailable: true,
				AuthenticatedData:  true,
				CheckingDisabled:   true,
				Rcode:              0,
			},
			Question: getQuestion(),
			Answer:   getResourceRecords(),
			Ns:       getResourceRecords(),
			Extra:    getResourceRecords(),
		},
		Error: nil,
	})

	msgs.AppendMessage(model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  "com.",
			Type:  2,
			Class: 1,
		},
		ResponseAddr: "2001:db8::1",
		NameServerIP: netip.MustParseAddr("2001:db8:123::123"),
		Metadata: model.Metadata{
			FromCache:     true,
			RetryIdx:      4,
			ConnId:        snowflake.ID(),
			TCP:           true,
			CorrelationId: snowflake.ID(),
			ParentId:      snowflake.ID(),
			EnqueueTime:   time.Now(),
			DequeueTime:   time.Now(),
		},
		Message: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: 4321,
			},
			Question: getQuestion(),
			Answer:   getResourceRecords(),
			Ns:       getResourceRecords(),
			Extra:    getResourceRecords(),
		},
		Error: nil,
	})

	nameServers := []*model.NameServer{
		{
			Name: model.MustNewDomainName(fmt.Sprintf("ns1.%v", domainName)),
			IPAddresses: common.NewCompSet(
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("2001:db8::1")),
		},
		{
			Name: model.MustNewDomainName(fmt.Sprintf("ns2.%v", domainName)),
			IPAddresses: common.NewCompSet(
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("2001:db8:db9::123")),
		},
	}

	return resolver.Result{
		Domains: []resolver.TaggedDomainName{{
			Name: model.MustNewDomainName(domainName),
		}},
		StartTime: time.Now(),
		Duration:  time.Duration(rand.Int63()),
		Zone: &model.Zone{
			Name:   ".",
			Parent: nil,
			Subzones: []*model.Zone{
				{
					Name:        "com.",
					Parent:      nil,
					Subzones:    nil,
					NameServers: nameServers,
				},
			},
			NameServers: nameServers,
		},
		Msgs: msgs,
	}
}

func getQuestion() []dns.Question {
	return []dns.Question{
		{
			Name:   "example.com.",
			Qtype:  1,
			Qclass: 1,
		},
		{
			Name:   "another.example.com.",
			Qtype:  2,
			Qclass: 2,
		},
	}
}

func getResourceRecords() []dns.RR {
	return []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "com.",
				Rrtype: 1,
				Class:  1,
				Ttl:    123,
			},
			A: net.ParseIP("198.51.100.1"),
		},
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "com.",
				Rrtype: 2,
				Class:  1,
				Ttl:    321,
			},
			Ns: "ns1.example.com.",
		},
	}
}

func getManyResourceRecords(n int) []dns.RR {
	result := make([]dns.RR, n)
	for i := 0; i < n; i++ {
		result[i] = &dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: 2,
				Class:  1,
				Ttl:    321,
			},
			Ns: fmt.Sprintf("ns%v.example.com.", i),
		}
	}
	return result
}
