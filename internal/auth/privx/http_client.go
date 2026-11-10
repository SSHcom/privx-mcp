package privx

import (
	"fmt"
	"net/http"
	"reflect"
	"time"
	"unsafe"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
)

// defaultPrivXHTTPTimeout bounds one PrivX HTTP call. The SDK client sets a
// dial timeout and no request timeout, so a host that accepts the connection
// and never answers would otherwise block the caller indefinitely.
const defaultPrivXHTTPTimeout = 30 * time.Second

// privxHTTPTimeout is the request timeout applied to SDK clients. Tests set a
// shorter value.
var privxHTTPTimeout = defaultPrivXHTTPTimeout

// boundHTTPClient sets the request timeout on an SDK connector. The client
// field is not exported, so the timeout is applied through the struct layout.
func boundHTTPClient(connector restapi.Connector) error {
	client, err := sdkHTTPClient(connector)
	if err != nil {
		return err
	}

	client.Timeout = privxHTTPTimeout

	return nil
}

func sdkHTTPClient(connector restapi.Connector) (*http.Client, error) {
	value := reflect.ValueOf(connector)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("privx connector is not an SDK client")
	}

	field, ok := value.Elem().Type().FieldByName("http")
	if !ok || field.Type != reflect.TypeFor[*http.Client]() {
		return nil, fmt.Errorf("privx connector has no http client")
	}

	clientPtr := (**http.Client)(unsafe.Add(value.UnsafePointer(), field.Offset))
	if clientPtr == nil || *clientPtr == nil {
		return nil, fmt.Errorf("privx connector http client is nil")
	}

	return *clientPtr, nil
}
