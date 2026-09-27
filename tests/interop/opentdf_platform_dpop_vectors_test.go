// Verifies opentdf-rs caller-key vectors against the opentdf-platform
// fork's own DPoP verifier.
//
// Targets Authentication.validateDPoP in opentdf-platform branch
// feat/agent-credentials-kas @ 08945d1e (service/internal/auth/authn.go),
// which returns (jwk.Key, bool, error): the bool reports whether the
// key-bound proof rules applied (cnf.jwk) rather than the cnf.jkt
// thumbprint check. These vectors bind via cnf.jkt, so it is always false.
//
// This file belongs to opentdf-rs. To record tests/data/dpop_interop_vectors.json,
// copy it into the fork's service/internal/auth/ and run it there; it is never
// committed to the fork.
package auth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

type opentdfRsVector struct {
	Name               string          `json:"name"`
	Alg                string          `json:"alg"`
	PublicJWK          json.RawMessage `json:"public_jwk"`
	AccessToken        string          `json:"access_token"`
	DPoP               string          `json:"dpop"`
	SignedRequestToken string          `json:"signed_request_token"`
}

func TestOpentdfRsDPoPVectors(t *testing.T) {
	path := os.Getenv("OPENTDF_RS_DPOP_VECTORS")
	if path == "" {
		t.Skip("set OPENTDF_RS_DPOP_VECTORS to opentdf-rs tests/data/dpop_interop_vectors.json")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var file struct {
		Vectors []opentdfRsVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.Len(t, file.Vectors, 2)

	// P1 adds EdDSA to the allow-list; before P1 lands, enable it the same way.
	if _, ok := allowedSignatureAlgorithms[jwa.EdDSA]; !ok {
		allowedSignatureAlgorithms[jwa.EdDSA] = true
		defer delete(allowedSignatureAlgorithms, jwa.EdDSA)
	}

	// The vectors carry a fixed past iat, so only the freshness window is
	// widened; every other check is the production one.
	a := Authentication{oidcConfiguration: AuthNConfig{DPoPSkew: 100 * 365 * 24 * time.Hour}}
	connectRewrap := receiverInfo{u: []string{"/kas.AccessService/Rewrap"}, m: []string{http.MethodPost}}
	fullURL := receiverInfo{u: []string{"https://platform.arkavo.net/kas.AccessService/Rewrap"}, m: []string{http.MethodPost}}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := jwk.ParseKey(v.PublicJWK)
			require.NoError(t, err)
			thumb, err := pub.Thumbprint(crypto.SHA256)
			require.NoError(t, err)
			access, err := jwt.NewBuilder().
				Claim("cnf", map[string]interface{}{"jkt": base64.RawURLEncoding.EncodeToString(thumb)}).
				Build()
			require.NoError(t, err)

			dpopKey, keyBound, err := a.validateDPoP(access, v.AccessToken, connectRewrap, []string{v.DPoP})
			require.NoError(t, err)
			// These vectors' access tokens carry cnf.jkt (a thumbprint), not
			// cnf.jwk, so the key-bound proof rules never apply here.
			require.False(t, keyBound)

			_, _, err = a.validateDPoP(access, v.AccessToken+"-other", connectRewrap, []string{v.DPoP})
			require.ErrorContains(t, err, "ath")

			_, _, err = a.validateDPoP(access, v.AccessToken, fullURL, []string{v.DPoP})
			require.ErrorContains(t, err, "htu")

			srt, err := jwt.Parse([]byte(v.SignedRequestToken),
				jwt.WithKey(jwa.SignatureAlgorithm(v.Alg), dpopKey), jwt.WithValidate(false))
			require.NoError(t, err)
			rb, ok := srt.Get("requestBody")
			require.True(t, ok)
			rbs, ok := rb.(string)
			require.True(t, ok)
			var req kas.UnsignedRewrapRequest
			require.NoError(t, protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(rbs), &req))
			require.NotEmpty(t, req.GetClientPublicKey())
			require.Len(t, req.GetRequests(), 1)
		})
	}
}
