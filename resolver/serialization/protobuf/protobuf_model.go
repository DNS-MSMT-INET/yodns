package protobuf

import (
	"encoding/binary"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/netip"
	"time"
)

const shortUUIDLength = 4
const longUUIDLength = 16
const snowflakeUUIDLength = 8

func (msg *MessageExchange) From(exchange *model.MessageExchange) error {
	msg.OriginalQuestion = &Question{
		Name:  string(exchange.OriginalQuestion.Name),
		Type:  uint32(exchange.OriginalQuestion.Type),
		Class: uint32(exchange.OriginalQuestion.Class),
	}
	msg.ResponseAddr = exchange.ResponseAddr
	msg.NameServerIp = exchange.NameServerIP.String()

	msg.Metadata = &Metadata{
		FromCache:     exchange.Metadata.FromCache,
		RetryIdx:      uint32(exchange.Metadata.RetryIdx),
		Tcp:           exchange.Metadata.TCP,
		EnqueueTime:   timestamppb.New(exchange.Metadata.EnqueueTime),
		DequeueTime:   timestamppb.New(exchange.Metadata.DequeueTime),
		IsFinal:       exchange.Metadata.IsFinal,
		Rtt:           int64(exchange.Metadata.RTT),
		ConnId:        make([]byte, 8),
		CorrelationId: make([]byte, 8),
		ParentId:      make([]byte, 8),
	}

	binary.BigEndian.PutUint64(msg.Metadata.ConnId, exchange.Metadata.ConnId)
	binary.BigEndian.PutUint64(msg.Metadata.CorrelationId, exchange.Metadata.CorrelationId)
	binary.BigEndian.PutUint64(msg.Metadata.ParentId, exchange.Metadata.ParentId)

	if exchange.Message != nil {
		if buf, err := exchange.Message.Pack(); err == nil {
			msg.Message = buf
		}
	}

	if exchange.Error != nil {
		msg.ErrorMessage = exchange.Error.Message
		msg.ErrorCode = string(exchange.Error.Code)
	}

	return nil
}

func (msg *MessageExchange) ToModel() (model.MessageExchange, error) {
	result := model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  model.MustNewDomainName(msg.OriginalQuestion.Name),
			Type:  uint16(msg.OriginalQuestion.Type),
			Class: uint16(msg.OriginalQuestion.Class),
		},
		ResponseAddr: msg.ResponseAddr,
		NameServerIP: netip.MustParseAddr(msg.NameServerIp),
		Metadata: model.Metadata{
			FromCache:   msg.Metadata.FromCache,
			RetryIdx:    uint(msg.Metadata.RetryIdx),
			TCP:         msg.Metadata.Tcp,
			EnqueueTime: msg.Metadata.EnqueueTime.AsTime(),
			DequeueTime: msg.Metadata.DequeueTime.AsTime(),
			IsFinal:     msg.Metadata.IsFinal,
			RTT:         time.Duration(msg.Metadata.Rtt),
		},
	}

	if len(msg.Message) > 0 {
		result.Message = new(dns.Msg)
		_ = result.Message.Unpack(msg.Message) // ignore the error (malformed messages may appear)
	}

	if msg.ErrorCode != "" || msg.ErrorMessage != "" {
		result.Error = &model.SendError{
			Message: msg.ErrorMessage,
			Code:    model.ErrorCode(msg.ErrorCode),
		}
	}

	var err error
	result.Metadata.CorrelationId, err = parseUUID(msg.Metadata.CorrelationId)
	if err != nil {
		return result, err
	}

	result.Metadata.ParentId, err = parseUUID(msg.Metadata.ParentId)
	if err != nil {
		return result, err
	}

	if len(msg.Metadata.ConnId) == 0 {
		result.Metadata.ConnId = 0
	} else if connID, err := parseUUID(msg.Metadata.ConnId); err == nil {
		result.Metadata.ConnId = connID
	}

	return result, nil
}

func parseUUID(bytes []byte) (uint64, error) {
	// Snowflake UUID length
	// This is the most recent UUID format we use
	if len(bytes) == snowflakeUUIDLength {
		return binary.BigEndian.Uint64(bytes), nil
	}

	// A full UUID - used in earlier versions of the software, but taking up too much storage.
	// For backwards compatibility, we read the last 8 bytes and convert it to a Snowflake UUID
	if len(bytes) == longUUIDLength {
		return binary.BigEndian.Uint64(bytes[:snowflakeUUIDLength]), nil
	}

	// Our "short UUID" is missing some bytes in the beginning to reduce storage needs.
	// Fill it up to full length before parsing
	if len(bytes) == shortUUIDLength {
		idBytes := make([]byte, snowflakeUUIDLength)
		copy(idBytes[snowflakeUUIDLength-shortUUIDLength:], bytes)
		return binary.BigEndian.Uint64(idBytes), nil
	}

	// Legacy: We used to store the uuid as string, but we still want to be able to parse the old files.
	if id, err := uuid.Parse(string(bytes)); err != nil {
		return 0, err
	} else {
		return binary.BigEndian.Uint64(id[:snowflakeUUIDLength]), nil
	}
}
