package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/federicoleon/golang-restclient/rest"
	"github.com/thanhftu/bookstore_utils-go/resterrors"
)

const (
	headerXPublic   = "x-public"
	headerXClientID = "x-client-id"
	headerXCallerID = "x-caller-id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthClient struct {
}

type oauthInterface interface {
}

// IsPublic check whether request is public or private
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

// GetCallerID return caller ID
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// GetClientID return clientID
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

// AuthenticateRequest check the request
func AuthenticateRequest(request *http.Request) resterrors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessTokenID := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	// http://api.bookstore.com/resource?access_token=abc123

	if accessTokenID == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, resterrors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/accesstoken/%s", accessTokenID))
	if response == nil || response.Response == nil {
		return nil, resterrors.NewInternalServerError("invalid restclient response when trying to get access token", errors.New("netword timeout"))
	}
	if response.StatusCode > 299 {
		restErr, err := resterrors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, resterrors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, resterrors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("error processing json"))
	}
	return &at, nil
}
