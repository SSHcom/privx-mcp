package oauth

import (
	"fmt"
	"net"
	"strconv"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
)

// RedirectURI is the value sent to the authorization server.
func RedirectURI(cb config.CallbackConfig) string {
	return fmt.Sprintf("http://%s:%d%s", cb.Host, cb.Port, cb.Path)
}

// BindHost is the address the callback listener binds. localhost is advertised
// in RedirectURI but the socket listens on 127.0.0.1.
func BindHost(advertiseHost string) string {
	if advertiseHost == "localhost" {
		return "127.0.0.1"
	}

	return advertiseHost
}

func listenAddr(cb config.CallbackConfig) string {
	return net.JoinHostPort(BindHost(cb.Host), strconv.Itoa(cb.Port))
}
