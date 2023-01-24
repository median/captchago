package captchago

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeHTTPS  ProxyType = "https"
	ProxyTypeSOCKS4 ProxyType = "socks4"
	ProxyTypeSOCKS5 ProxyType = "socks5"
)

func ParseProxy(proxyUrl string) (*Proxy, error) {
	parsed, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, err
	}

	var login *ProxyLogon
	if parsed.User != nil {
		pass, _ := parsed.User.Password()
		login = &ProxyLogon{
			Username: parsed.User.Username(),
			Password: pass,
		}
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return nil, err
	}

	p := NewProxy(parsed.Scheme, parsed.Hostname(), port, login)
	if p == nil {
		return nil, errors.New("invalid proxy type")
	}

	return p, nil
}

func NewProxy(t ProxyType, address string, port int, login *ProxyLogon) *Proxy {
	t = strings.TrimSpace(strings.ToLower(t))
	if t != ProxyTypeHTTP && t != ProxyTypeHTTPS && t != ProxyTypeSOCKS4 && t != ProxyTypeSOCKS5 {
		return nil
	}

	return &Proxy{
		pType:   t,
		address: address,
		port:    port,
		login:   login,
	}
}

func (p *Proxy) String() string {
	if p == nil {
		return ""
	}

	return p.login.String() + p.address + ":" + strconv.Itoa(p.port)
}

func (pl *ProxyLogon) String() string {
	if pl == nil {
		return ""
	}

	return pl.Username + ":" + pl.Password + "@"
}

type Proxy struct {
	address string
	port    int
	pType   ProxyType
	login   *ProxyLogon
}

type ProxyLogon struct {
	Username string
	Password string
}

type ProxyType = string
