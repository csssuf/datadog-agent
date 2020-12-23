package snmp

import (
	"fmt"
	"github.com/soniah/gosnmp"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_snmpSession_Configure(t *testing.T) {
	tests := []struct {
		name                       string
		config                     snmpConfig
		expectedError              error
		expectedVersion            gosnmp.SnmpVersion
		expectedTimeout            time.Duration
		expectedRetries            int
		expectedCommunity          string
		expectedMsgFlags           gosnmp.SnmpV3MsgFlags
		expectedContextName        string
		expectedSecurityParameters gosnmp.SnmpV3SecurityParameters
	}{
		{
			name: "valid v2 config",
			config: snmpConfig{
				IPAddress:       "1.2.3.4",
				Port:            uint16(1234),
				SnmpVersion:     gosnmp.Version2c,
				Timeout:         4,
				Retries:         3,
				CommunityString: "abc",
			},
			expectedVersion:   gosnmp.Version2c,
			expectedError:     nil,
			expectedTimeout:   time.Duration(4) * time.Second,
			expectedRetries:   3,
			expectedCommunity: "abc",
			expectedMsgFlags:  gosnmp.NoAuthNoPriv,
		},
		{
			name: "valid v3 AuthPriv config",
			config: snmpConfig{
				IPAddress:    "1.2.3.4",
				Port:         uint16(1234),
				SnmpVersion:  gosnmp.Version3,
				Timeout:      4,
				Retries:      3,
				ContextName:  "myContext",
				User:         "myUser",
				AuthKey:      "myAuthKey",
				AuthProtocol: "md5",
				PrivKey:      "myPrivKey",
				PrivProtocol: "aes",
			},
			expectedVersion:     gosnmp.Version3,
			expectedError:       nil,
			expectedTimeout:     time.Duration(4) * time.Second,
			expectedRetries:     3,
			expectedCommunity:   "",
			expectedMsgFlags:    gosnmp.AuthPriv,
			expectedContextName: "myContext",
			expectedSecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 "myUser",
				AuthenticationProtocol:   gosnmp.MD5,
				AuthenticationPassphrase: "myAuthKey",
				PrivacyProtocol:          gosnmp.AES,
				PrivacyPassphrase:        "myPrivKey",
			},
		},
		{
			name: "valid v3 AuthNoPriv config",
			config: snmpConfig{
				IPAddress:    "1.2.3.4",
				Port:         uint16(1234),
				SnmpVersion:  gosnmp.Version3,
				Timeout:      4,
				Retries:      3,
				User:         "myUser",
				AuthKey:      "myAuthKey",
				AuthProtocol: "md5",
			},
			expectedVersion:   gosnmp.Version3,
			expectedError:     nil,
			expectedTimeout:   time.Duration(4) * time.Second,
			expectedRetries:   3,
			expectedCommunity: "",
			expectedMsgFlags:  gosnmp.AuthNoPriv,
			expectedSecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 "myUser",
				AuthenticationProtocol:   gosnmp.MD5,
				AuthenticationPassphrase: "myAuthKey",
				PrivacyProtocol:          gosnmp.NoPriv,
				PrivacyPassphrase:        "",
			},
		},
		{
			name: "invalid v3 AuthProtocol",
			config: snmpConfig{
				IPAddress:    "1.2.3.4",
				Port:         uint16(1234),
				SnmpVersion:  gosnmp.Version3,
				Timeout:      4,
				Retries:      3,
				User:         "myUser",
				AuthKey:      "myAuthKey",
				AuthProtocol: "invalid",
			},
			expectedVersion:            gosnmp.Version1, // default, not configured
			expectedError:              fmt.Errorf("unsupported authentication protocol: invalid"),
			expectedSecurityParameters: nil, // default, not configured
		},
		{
			name: "invalid v3 PrivProtocol",
			config: snmpConfig{
				IPAddress:    "1.2.3.4",
				Port:         uint16(1234),
				SnmpVersion:  gosnmp.Version3,
				Timeout:      4,
				Retries:      3,
				User:         "myUser",
				AuthKey:      "myAuthKey",
				AuthProtocol: "md5",
				PrivKey:      "myPrivKey",
				PrivProtocol: "invalid",
			},
			expectedVersion:            gosnmp.Version1, // default, not configured
			expectedError:              fmt.Errorf("unsupported privacy protocol: invalid"),
			expectedSecurityParameters: nil, // default, not configured
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &snmpSession{}
			err := s.Configure(tt.config)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedVersion, s.gosnmpInst.Version)
			assert.Equal(t, tt.expectedRetries, s.gosnmpInst.Retries)
			assert.Equal(t, tt.expectedTimeout, s.gosnmpInst.Timeout)
			assert.Equal(t, tt.expectedCommunity, s.gosnmpInst.Community)
			assert.Equal(t, tt.expectedContextName, s.gosnmpInst.ContextName)
			assert.Equal(t, tt.expectedMsgFlags, s.gosnmpInst.MsgFlags)
			assert.Equal(t, tt.expectedSecurityParameters, s.gosnmpInst.SecurityParameters)
		})
	}
}
