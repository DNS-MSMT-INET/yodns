// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package json

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
	model "github.com/DNS-MSMT-INET/yodns/resolver/model"
	netip "net/netip"
	time "time"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(in *jlexer.Lexer, out *Zone) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = string(in.String())
		case "Subzones":
			if in.IsNull() {
				in.Skip()
				out.Subzones = nil
			} else {
				in.Delim('[')
				if out.Subzones == nil {
					if !in.IsDelim(']') {
						out.Subzones = make([]Zone, 0, 0)
					} else {
						out.Subzones = []Zone{}
					}
				} else {
					out.Subzones = (out.Subzones)[:0]
				}
				for !in.IsDelim(']') {
					var v1 Zone
					(v1).UnmarshalEasyJSON(in)
					out.Subzones = append(out.Subzones, v1)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "NameServers":
			if in.IsNull() {
				in.Skip()
				out.NameServers = nil
			} else {
				in.Delim('[')
				if out.NameServers == nil {
					if !in.IsDelim(']') {
						out.NameServers = make([]NameServer, 0, 1)
					} else {
						out.NameServers = []NameServer{}
					}
				} else {
					out.NameServers = (out.NameServers)[:0]
				}
				for !in.IsDelim(']') {
					var v2 NameServer
					(v2).UnmarshalEasyJSON(in)
					out.NameServers = append(out.NameServers, v2)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "ResourceRecords":
			if in.IsNull() {
				in.Skip()
				out.ResourceRecords = nil
			} else {
				in.Delim('[')
				if out.ResourceRecords == nil {
					if !in.IsDelim(']') {
						out.ResourceRecords = make([]string, 0, 4)
					} else {
						out.ResourceRecords = []string{}
					}
				} else {
					out.ResourceRecords = (out.ResourceRecords)[:0]
				}
				for !in.IsDelim(']') {
					var v3 string
					v3 = string(in.String())
					out.ResourceRecords = append(out.ResourceRecords, v3)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(out *jwriter.Writer, in Zone) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"Subzones\":"
		out.RawString(prefix)
		if in.Subzones == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v4, v5 := range in.Subzones {
				if v4 > 0 {
					out.RawByte(',')
				}
				(v5).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"NameServers\":"
		out.RawString(prefix)
		if in.NameServers == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v6, v7 := range in.NameServers {
				if v6 > 0 {
					out.RawByte(',')
				}
				(v7).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"ResourceRecords\":"
		out.RawString(prefix)
		if in.ResourceRecords == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v8, v9 := range in.ResourceRecords {
				if v8 > 0 {
					out.RawByte(',')
				}
				out.String(string(v9))
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Zone) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Zone) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Zone) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Zone) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(in *jlexer.Lexer, out *WriteModel) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Domains":
			if in.IsNull() {
				in.Skip()
				out.Domains = nil
			} else {
				in.Delim('[')
				if out.Domains == nil {
					if !in.IsDelim(']') {
						out.Domains = make([]TaggedDomain, 0, 1)
					} else {
						out.Domains = []TaggedDomain{}
					}
				} else {
					out.Domains = (out.Domains)[:0]
				}
				for !in.IsDelim(']') {
					var v10 TaggedDomain
					(v10).UnmarshalEasyJSON(in)
					out.Domains = append(out.Domains, v10)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "StartTime":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.StartTime).UnmarshalJSON(data))
			}
		case "Duration":
			out.Duration = time.Duration(in.Int64())
		case "Zonedata":
			(out.Zonedata).UnmarshalEasyJSON(in)
		case "Messages":
			if in.IsNull() {
				in.Skip()
				out.Messages = nil
			} else {
				in.Delim('[')
				if out.Messages == nil {
					if !in.IsDelim(']') {
						out.Messages = make([]MessageExchange, 0, 0)
					} else {
						out.Messages = []MessageExchange{}
					}
				} else {
					out.Messages = (out.Messages)[:0]
				}
				for !in.IsDelim(']') {
					var v11 MessageExchange
					(v11).UnmarshalEasyJSON(in)
					out.Messages = append(out.Messages, v11)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(out *jwriter.Writer, in WriteModel) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Domains\":"
		out.RawString(prefix[1:])
		if in.Domains == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v12, v13 := range in.Domains {
				if v12 > 0 {
					out.RawByte(',')
				}
				(v13).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"StartTime\":"
		out.RawString(prefix)
		out.Raw((in.StartTime).MarshalJSON())
	}
	{
		const prefix string = ",\"Duration\":"
		out.RawString(prefix)
		out.Int64(int64(in.Duration))
	}
	{
		const prefix string = ",\"Zonedata\":"
		out.RawString(prefix)
		(in.Zonedata).MarshalEasyJSON(out)
	}
	{
		const prefix string = ",\"Messages\":"
		out.RawString(prefix)
		if in.Messages == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v14, v15 := range in.Messages {
				if v14 > 0 {
					out.RawByte(',')
				}
				(v15).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v WriteModel) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v WriteModel) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *WriteModel) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *WriteModel) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson1(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(in *jlexer.Lexer, out *TaggedDomain) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Idx":
			out.Idx = uint(in.Uint())
		case "Name":
			out.Name = model.DomainName(in.String())
		case "Tags":
			out.Tags = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(out *jwriter.Writer, in TaggedDomain) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Idx\":"
		out.RawString(prefix[1:])
		out.Uint(uint(in.Idx))
	}
	{
		const prefix string = ",\"Name\":"
		out.RawString(prefix)
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"Tags\":"
		out.RawString(prefix)
		out.String(string(in.Tags))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v TaggedDomain) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v TaggedDomain) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *TaggedDomain) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *TaggedDomain) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson2(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(in *jlexer.Lexer, out *ResourceRecord) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = string(in.String())
		case "Type":
			out.Type = uint16(in.Uint16())
		case "Class":
			out.Class = uint16(in.Uint16())
		case "TTL":
			out.TTL = uint32(in.Uint32())
		case "Value":
			out.Value = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(out *jwriter.Writer, in ResourceRecord) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"Type\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.Type))
	}
	{
		const prefix string = ",\"Class\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.Class))
	}
	{
		const prefix string = ",\"TTL\":"
		out.RawString(prefix)
		out.Uint32(uint32(in.TTL))
	}
	{
		const prefix string = ",\"Value\":"
		out.RawString(prefix)
		out.String(string(in.Value))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ResourceRecord) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ResourceRecord) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ResourceRecord) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ResourceRecord) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson3(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(in *jlexer.Lexer, out *NameServer) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = string(in.String())
		case "IPAddresses":
			if in.IsNull() {
				in.Skip()
				out.IPAddresses = nil
			} else {
				in.Delim('[')
				if out.IPAddresses == nil {
					if !in.IsDelim(']') {
						out.IPAddresses = make([]netip.Addr, 0, 2)
					} else {
						out.IPAddresses = []netip.Addr{}
					}
				} else {
					out.IPAddresses = (out.IPAddresses)[:0]
				}
				for !in.IsDelim(']') {
					var v16 netip.Addr
					if data := in.UnsafeBytes(); in.Ok() {
						in.AddError((v16).UnmarshalText(data))
					}
					out.IPAddresses = append(out.IPAddresses, v16)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(out *jwriter.Writer, in NameServer) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"IPAddresses\":"
		out.RawString(prefix)
		if in.IPAddresses == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v17, v18 := range in.IPAddresses {
				if v17 > 0 {
					out.RawByte(',')
				}
				out.RawText((v18).MarshalText())
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v NameServer) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v NameServer) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *NameServer) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *NameServer) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson4(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(in *jlexer.Lexer, out *MessageExchange) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "OriginalQuestion":
			easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel(in, &out.OriginalQuestion)
		case "ResponseAddr":
			out.ResponseAddr = string(in.String())
		case "NameServerIP":
			if data := in.UnsafeBytes(); in.Ok() {
				in.AddError((out.NameServerIP).UnmarshalText(data))
			}
		case "Metadata":
			easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel1(in, &out.Metadata)
		case "Message":
			if in.IsNull() {
				in.Skip()
				out.Message = nil
			} else {
				if out.Message == nil {
					out.Message = new(Message)
				}
				(*out.Message).UnmarshalEasyJSON(in)
			}
		case "Error":
			if in.IsNull() {
				in.Skip()
				out.Error = nil
			} else {
				if out.Error == nil {
					out.Error = new(model.SendError)
				}
				easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel2(in, out.Error)
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(out *jwriter.Writer, in MessageExchange) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"OriginalQuestion\":"
		out.RawString(prefix[1:])
		easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel(out, in.OriginalQuestion)
	}
	{
		const prefix string = ",\"ResponseAddr\":"
		out.RawString(prefix)
		out.String(string(in.ResponseAddr))
	}
	{
		const prefix string = ",\"NameServerIP\":"
		out.RawString(prefix)
		out.RawText((in.NameServerIP).MarshalText())
	}
	{
		const prefix string = ",\"Metadata\":"
		out.RawString(prefix)
		easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel1(out, in.Metadata)
	}
	{
		const prefix string = ",\"Message\":"
		out.RawString(prefix)
		if in.Message == nil {
			out.RawString("null")
		} else {
			(*in.Message).MarshalEasyJSON(out)
		}
	}
	{
		const prefix string = ",\"Error\":"
		out.RawString(prefix)
		if in.Error == nil {
			out.RawString("null")
		} else {
			easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel2(out, *in.Error)
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v MessageExchange) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v MessageExchange) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *MessageExchange) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *MessageExchange) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson5(l, v)
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel2(in *jlexer.Lexer, out *model.SendError) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Message":
			out.Message = string(in.String())
		case "Code":
			out.Code = model.ErrorCode(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel2(out *jwriter.Writer, in model.SendError) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Message\":"
		out.RawString(prefix[1:])
		out.String(string(in.Message))
	}
	{
		const prefix string = ",\"Code\":"
		out.RawString(prefix)
		out.String(string(in.Code))
	}
	out.RawByte('}')
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel1(in *jlexer.Lexer, out *model.Metadata) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "FromCache":
			out.FromCache = bool(in.Bool())
		case "RetryIdx":
			out.RetryIdx = uint(in.Uint())
		case "ConnId":
			out.ConnId = string(in.String())
		case "TCP":
			out.TCP = bool(in.Bool())
		case "IsFinal":
			out.IsFinal = bool(in.Bool())
		case "CorrelationId":
			if data := in.UnsafeBytes(); in.Ok() {
				in.AddError((out.CorrelationId).UnmarshalText(data))
			}
		case "ParentId":
			if data := in.UnsafeBytes(); in.Ok() {
				in.AddError((out.ParentId).UnmarshalText(data))
			}
		case "EnqueueTime":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.EnqueueTime).UnmarshalJSON(data))
			}
		case "DequeueTime":
			if data := in.Raw(); in.Ok() {
				in.AddError((out.DequeueTime).UnmarshalJSON(data))
			}
		case "RTT":
			out.RTT = time.Duration(in.Int64())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel1(out *jwriter.Writer, in model.Metadata) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"FromCache\":"
		out.RawString(prefix[1:])
		out.Bool(bool(in.FromCache))
	}
	{
		const prefix string = ",\"RetryIdx\":"
		out.RawString(prefix)
		out.Uint(uint(in.RetryIdx))
	}
	{
		const prefix string = ",\"ConnId\":"
		out.RawString(prefix)
		out.String(string(in.ConnId))
	}
	{
		const prefix string = ",\"TCP\":"
		out.RawString(prefix)
		out.Bool(bool(in.TCP))
	}
	{
		const prefix string = ",\"IsFinal\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsFinal))
	}
	{
		const prefix string = ",\"CorrelationId\":"
		out.RawString(prefix)
		out.RawText((in.CorrelationId).MarshalText())
	}
	{
		const prefix string = ",\"ParentId\":"
		out.RawString(prefix)
		out.RawText((in.ParentId).MarshalText())
	}
	{
		const prefix string = ",\"EnqueueTime\":"
		out.RawString(prefix)
		out.Raw((in.EnqueueTime).MarshalJSON())
	}
	{
		const prefix string = ",\"DequeueTime\":"
		out.RawString(prefix)
		out.Raw((in.DequeueTime).MarshalJSON())
	}
	{
		const prefix string = ",\"RTT\":"
		out.RawString(prefix)
		out.Int64(int64(in.RTT))
	}
	out.RawByte('}')
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel(in *jlexer.Lexer, out *model.Question) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Name":
			out.Name = model.DomainName(in.String())
		case "Type":
			out.Type = uint16(in.Uint16())
		case "Class":
			out.Class = uint16(in.Uint16())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverModel(out *jwriter.Writer, in model.Question) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Name\":"
		out.RawString(prefix[1:])
		out.String(string(in.Name))
	}
	{
		const prefix string = ",\"Type\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.Type))
	}
	{
		const prefix string = ",\"Class\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.Class))
	}
	out.RawByte('}')
}
func easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(in *jlexer.Lexer, out *Message) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "Id":
			out.Id = uint16(in.Uint16())
		case "RCode":
			out.RCode = int(in.Int())
		case "Opcode":
			out.Opcode = int(in.Int())
		case "IsResponse":
			out.IsResponse = bool(in.Bool())
		case "IsAuthoritative":
			out.IsAuthoritative = bool(in.Bool())
		case "IsTruncated":
			out.IsTruncated = bool(in.Bool())
		case "IsRecursionDesired":
			out.IsRecursionDesired = bool(in.Bool())
		case "IsRecursionAvailable":
			out.IsRecursionAvailable = bool(in.Bool())
		case "IsAuthenticatedData":
			out.IsAuthenticatedData = bool(in.Bool())
		case "IsCheckingDisabled":
			out.IsCheckingDisabled = bool(in.Bool())
		case "Question":
			if in.IsNull() {
				in.Skip()
				out.Question = nil
			} else {
				in.Delim('[')
				if out.Question == nil {
					if !in.IsDelim(']') {
						out.Question = make([]ResourceRecord, 0, 1)
					} else {
						out.Question = []ResourceRecord{}
					}
				} else {
					out.Question = (out.Question)[:0]
				}
				for !in.IsDelim(']') {
					var v19 ResourceRecord
					(v19).UnmarshalEasyJSON(in)
					out.Question = append(out.Question, v19)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "Answer":
			if in.IsNull() {
				in.Skip()
				out.Answer = nil
			} else {
				in.Delim('[')
				if out.Answer == nil {
					if !in.IsDelim(']') {
						out.Answer = make([]ResourceRecord, 0, 1)
					} else {
						out.Answer = []ResourceRecord{}
					}
				} else {
					out.Answer = (out.Answer)[:0]
				}
				for !in.IsDelim(']') {
					var v20 ResourceRecord
					(v20).UnmarshalEasyJSON(in)
					out.Answer = append(out.Answer, v20)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "Authority":
			if in.IsNull() {
				in.Skip()
				out.Authority = nil
			} else {
				in.Delim('[')
				if out.Authority == nil {
					if !in.IsDelim(']') {
						out.Authority = make([]ResourceRecord, 0, 1)
					} else {
						out.Authority = []ResourceRecord{}
					}
				} else {
					out.Authority = (out.Authority)[:0]
				}
				for !in.IsDelim(']') {
					var v21 ResourceRecord
					(v21).UnmarshalEasyJSON(in)
					out.Authority = append(out.Authority, v21)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "Additional":
			if in.IsNull() {
				in.Skip()
				out.Additional = nil
			} else {
				in.Delim('[')
				if out.Additional == nil {
					if !in.IsDelim(']') {
						out.Additional = make([]ResourceRecord, 0, 1)
					} else {
						out.Additional = []ResourceRecord{}
					}
				} else {
					out.Additional = (out.Additional)[:0]
				}
				for !in.IsDelim(']') {
					var v22 ResourceRecord
					(v22).UnmarshalEasyJSON(in)
					out.Additional = append(out.Additional, v22)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "OriginalBytes":
			out.OriginalBytes = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(out *jwriter.Writer, in Message) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"Id\":"
		out.RawString(prefix[1:])
		out.Uint16(uint16(in.Id))
	}
	{
		const prefix string = ",\"RCode\":"
		out.RawString(prefix)
		out.Int(int(in.RCode))
	}
	{
		const prefix string = ",\"Opcode\":"
		out.RawString(prefix)
		out.Int(int(in.Opcode))
	}
	{
		const prefix string = ",\"IsResponse\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsResponse))
	}
	{
		const prefix string = ",\"IsAuthoritative\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsAuthoritative))
	}
	{
		const prefix string = ",\"IsTruncated\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsTruncated))
	}
	{
		const prefix string = ",\"IsRecursionDesired\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsRecursionDesired))
	}
	{
		const prefix string = ",\"IsRecursionAvailable\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsRecursionAvailable))
	}
	{
		const prefix string = ",\"IsAuthenticatedData\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsAuthenticatedData))
	}
	{
		const prefix string = ",\"IsCheckingDisabled\":"
		out.RawString(prefix)
		out.Bool(bool(in.IsCheckingDisabled))
	}
	{
		const prefix string = ",\"Question\":"
		out.RawString(prefix)
		if in.Question == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v23, v24 := range in.Question {
				if v23 > 0 {
					out.RawByte(',')
				}
				(v24).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"Answer\":"
		out.RawString(prefix)
		if in.Answer == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v25, v26 := range in.Answer {
				if v25 > 0 {
					out.RawByte(',')
				}
				(v26).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"Authority\":"
		out.RawString(prefix)
		if in.Authority == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v27, v28 := range in.Authority {
				if v27 > 0 {
					out.RawByte(',')
				}
				(v28).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"Additional\":"
		out.RawString(prefix)
		if in.Additional == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v29, v30 := range in.Additional {
				if v29 > 0 {
					out.RawByte(',')
				}
				(v30).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	{
		const prefix string = ",\"OriginalBytes\":"
		out.RawString(prefix)
		out.String(string(in.OriginalBytes))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Message) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Message) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Message) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Message) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGitlabMpiKlsbMpgDeFsteurerYodnsResolverSerializationJson6(l, v)
}
