package asn_match_database

import (
	"os"
	"testing"
)

type tlsFixtures struct {
	caCertPath     string
	clientCertPath string
	clientKeyPath  string
	invalidPEMPath string
	emptyFilePath  string
}

// createTLSFixtures writes a handful of PEM fixtures to a temp directory for TLS validation tests.
func createTLSFixtures(t *testing.T) tlsFixtures {
	t.Helper()

	dir := t.TempDir()

	validCACert := `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUaCFiKhxzR0PFY0y0JaDFT8DperEwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTExMjIwMTMwNDVaFw0yNTExMjMw
MTMwNDVaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQD0n6a8P9NWNVAT9ZLAMxQ7VRXkTG4Q/yy49WKgAoyBugdtiQms
fS1PS/adZ3jbLMskP8yQWfvPBh/OiuX1w+XlBTU01GPxyM+LCf3eUXLbZidU/lfg
gw+pOOgZhbjHa7UGfghC6oLoU09KBvqmu2GmDbMDdZV1alTjV2fHpk3kNUOJlPDu
CiquI8QSME12pjqFqDh24s6o+t38E2Zmp/QR0Sc2Da/C+dTfL8kPE95W4oZvGQu/
h1kwV4S5EK8X5aY9emKTTv1F9NyST+/dFPgHgvJwzG0Qq9M2nNXcUfPWxI/ujT6F
PdN663FX8LOS8Xp4tACBklBddoiOhbzIr/SXAgMBAAGjUzBRMB0GA1UdDgQWBBQB
YgxNkh3VD3lqzcF/rvJPNVbAKDAfBgNVHSMEGDAWgBQBYgxNkh3VD3lqzcF/rvJP
NVbAKDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8pZi+24rM
O2JPea4cd1dnlOtDp38P1tTRpNMLVJhpyvBiX7YGLUhl5GmQhBzxWWErUvn32tZt
C89BrCS4ZSskLUHG7FpPHGMAyvYT6mbZGTw/yTPXr3nuy62LmQ6UclgP5gYh1Oji
SSsjutbhgat3aKklZSL9gj3cEu7Wc+lCs9T1VOtfvGiGiCs6n1HxYxqnKWFAcBsx
qODr37opF9g0HAZ+YfZpa1YkR/oHwU6FE1zZz90hcK1tw4OJ7OqfF4YmFUkzv2mL
Wu3tnlNTuQ+i2do6BGQS6OzJYfoJ9coOL4cZTFnHPtlUkXf0cS0SchbCjOnoTgJA
8gXAxi6swCc+
-----END CERTIFICATE-----`

	validClientCert := `-----BEGIN CERTIFICATE-----
MIIC+DCCAeCgAwIBAgIUAzkRYH45BCQ9v7qhslH0IzTUK1MwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNTExMjIwMTMwNDZaFw0yNTExMjMw
MTMwNDZaMBYxFDASBgNVBAMMC1Rlc3QgQ2xpZW50MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAzvhC+l+DsxXfxlsioMwUpN95Qi3sZAfvcywEGxTmtEgC
88SVDPchGaiIYxnFOtd4ItRbJeWK28fnn+nPA2FNF1AbMEWxmtl/AAF0pUQtJgg2
7wlZgU2thsxw6U8TsFsItgBfOzj3pwMNzi6EGtg1sO30t49QpJitLxNholZE7fef
tEnV3bzVzzPiOznrcQTe/opc1UUg1ZdFHoCwo+HMIPlhc8DiiszhXiFvqToWZde2
JFpODMmsCv1Um/1k8FFXW2K2+sarkT7B2cveky5dgwo0CRR/hKgxVVEX8+rKaPsg
I7+2Oo1XGJFK1BhleZviGau0d5OaROUZHy2Z8XcAgwIDAQABo0IwQDAdBgNVHQ4E
FgQUb7ReT9zqZa6s+55G4ix3BxwPDwYwHwYDVR0jBBgwFoAUAWIMTZId1Q95as3B
f67yTzVWwCgwDQYJKoZIhvcNAQELBQADggEBAPQHrhCCY9M9ByeCQXXQKB3tQoMU
NfeW9KCY1DrjHRX4nGf698eGn3Qm4Lis/D2/VuxdG2hYN6NMmFMZ4HyOP+wlE3mN
ZuBEVrW4HyMy8j2i0jdk2pUHs0iJC4qgtfBC0PakShaLWoZ46mIf04XIhCpVl5XE
3DxrfVe6TeS1BXUJvZhB109H4KJ2mV39Oe77gPCRU8lTlFJTzwf0lYeqySqNbvlQ
+I+K+5z4ICexBrdlBtxdTHV3xR9QywMEn4hQcuyZCK/Nb9tB0Y0a0qpGO0gITnSd
hgttjW+dSem0k697yLD2O9sEkWEbSAJCRYhYDFm/uxJmGI7tu0jC4XAtdbI=
-----END CERTIFICATE-----`

	validClientKey := `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDO+EL6X4OzFd/G
WyKgzBSk33lCLexkB+9zLAQbFOa0SALzxJUM9yEZqIhjGcU613gi1Fsl5Yrbx+ef
6c8DYU0XUBswRbGa2X8AAXSlRC0mCDbvCVmBTa2GzHDpTxOwWwi2AF87OPenAw3O
LoQa2DWw7fS3j1CkmK0vE2GiVkTt95+0SdXdvNXPM+I7OetxBN7+ilzVRSDVl0Ue
gLCj4cwg+WFzwOKKzOFeIW+pOhZl17YkWk4MyawK/VSb/WTwUVdbYrb6xquRPsHZ
y96TLl2DCjQJFH+EqDFVURfz6spo+yAjv7Y6jVcYkUrUGGV5m+IZq7R3k5pE5Rkf
LZnxdwCDAgMBAAECggEAFKJ/2wKG2OYHZ3lSnIF8VWvKZSS6+sYnw23SAvk0fyjm
0nL5AU/qRuqcnnTFSzaMTbyqUb7u9zaZC0J+VzHuQ7LC4y8vo+anWNLMVGXVsoMD
JxXhjJi4AkaDw18U8XJCDhM/a2IknswZJkNQ/HQt9jPjQCHTwnVOXvEpvMupF6h4
p5Yt5OBbFu7KQO+SVhEgBS5CigujLXrKyDhxvOoDKLlJ5vw2GY0vTSekCk/bFzC4
SGLL/hRM4m6scvxahwXQm1hiC7H7BAxsvXdiNFAKSgfm+bw2dI1R7YA6//HKQdbJ
W3PIDN4vc4GDrOvzCo3rrPNpTP72nZX2iFai0e7pwQKBgQDmjkZYai/KPqA4lWVF
JOCo7VzqHBbduj64GR5eCo4tuus/yoaTBw1PxIseBelaeH065Nzd5LDgIsfwje43
IsRCYgdO1PGggfwDXshH2XI/qY5PViW7ihFSlsLw8p8WNr/MZ/5MK9NN2HhuDXn6
FVAe528IDRBNkgzIrwg41pDuUQKBgQDlz6EDP26koOFZQwa/72KU8sNcTPWjhf6B
dmiX0LyJ/xLO+y/stnmPeI+cjSTMQ2ZBiD5YEOQZ7J0utJ6siNEItFyvN3ZHZSob
u3+5Dw7/SV+lActC5BvnzUfYKy/g4CYLegu369j5v1CbpGP3AicAwKbXLy88OL0K
X3zwjwmokwKBgQCDf1RJ606UmIGDpFndRPpJ/w/GivzTu/03vUPfuT98f6bbfGSj
CRujimMaXZ7Jtf0fEReUC3KCc/P7lMfwdIjhn82xPa0OsfSN64ppyHDsNIXxZB4j
R803gLtw98Cax+E+8XVN9pUPSk7t3gvbAjrvVWqzedf5ljpqX8JdwKtq8QKBgQC4
LD/TxIA9e5ld2fOM2qJc0Hl0fVDW7knbIzQLhwOybDN8oZ30zQB61JnzUsJM2S8Y
EcI0/cRwakpF5gbMKxGrMjCdU4t9CDxI4WkovEK+oOT/7oIhZ4JdsQyE14eVZs3W
oMbHbUIEVSias5JRoO31EnAjP/NRBf+qUoBkoZ2R9QKBgQDiJtxsGhL6xbMEvFbm
dV2ocV3S3IITb6o2REQd0hkfw61+Hwtg7Lg3zXur7H40TXYh6+Exk+d89qKSgEtd
EjLTlIz4NzkyO8743eO/ni0usiEkuPQWis90A5/dqBVpenatsrJq+UP01PCPVuhU
IyfSCo7lmG8mSL2Gk5GWE8uOiQ==
-----END PRIVATE KEY-----`

	fixtures := tlsFixtures{
		caCertPath:     dir + "/ca.pem",
		clientCertPath: dir + "/client.pem",
		clientKeyPath:  dir + "/client-key.pem",
		invalidPEMPath: dir + "/invalid.pem",
		emptyFilePath:  dir + "/empty.pem",
	}

	if err := os.WriteFile(fixtures.caCertPath, []byte(validCACert), 0o600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(fixtures.clientCertPath, []byte(validClientCert), 0o600); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}
	if err := os.WriteFile(fixtures.clientKeyPath, []byte(validClientKey), 0o600); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}
	if err := os.WriteFile(fixtures.invalidPEMPath, []byte("not a PEM file"), 0o600); err != nil {
		t.Fatalf("failed to write invalid PEM: %v", err)
	}
	if err := os.WriteFile(fixtures.emptyFilePath, []byte(""), 0o600); err != nil {
		t.Fatalf("failed to write empty PEM file: %v", err)
	}

	return fixtures
}

// setEnv sets an env var and restores its previous value after the test.
func setEnv(t *testing.T, key, value string) {
	t.Helper()

	original, had := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("failed to set env %s: %v", key, err)
	}

	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, original)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}
