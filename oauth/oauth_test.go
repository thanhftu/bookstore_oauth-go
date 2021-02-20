package oauth

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	fmt.Println("start oauth test")
	rest.StartMockupServer()
	os.Exit(m.Run())
}
func TestOauthConstants(t *testing.T) {
	require.EqualValues(t, "x-public", headerXPublic)
	require.EqualValues(t, "x-client-id", headerXClientID)
	require.EqualValues(t, "x-caller-id", headerXCallerID)
	require.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	require.True(t, IsPublic(nil))
}
func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	require.False(t, IsPublic(&request))

	request.Header.Add("x-public", "true")
	require.True(t, IsPublic(&request))
}

func TestGetCallerIDNilRequest(t *testing.T) {

}

func TestGetCallerIDInvalidCallerFormat(t *testing.T) {

}

func TestGetCallerIDNoError(t *testing.T) {

}

func TestGetAccessTokenInvalidRestclientResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/accesstoken/AbC123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{}`,
	})

	accessToken, err := getAccessToken("AbC123")
	require.Nil(t, accessToken)
	require.NotNil(t, err)
	require.EqualValues(t, http.StatusInternalServerError, err.Status())
	require.EqualValues(t, "invalid restclient response when trying to get access token", err.Message())
}
