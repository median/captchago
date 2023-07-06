package captchago

import (
	"errors"
)

type solveMethods struct {
	GetBalance  func() (float64, error)
	RecaptchaV2 func(RecaptchaV2Options) (*Solution, error)
	RecaptchaV3 func(RecaptchaV3Options) (*Solution, error)
	HCaptcha    func(HCaptchaOptions) (*Solution, error)
	FunCaptcha  func(FunCaptchaOptions) (*Solution, error)
	Kasada      func(KasadaOptions) (*KasadaSolution, error)
	Cloudflare  func(CloudflareOptions) (*Solution, error)
}

// GetBalance returns the balance of the account
func (s *Solver) GetBalance() (float64, error) {
	if s.methods.GetBalance == nil {
		return 0, errors.New("service does not support getBalance")
	}
	return s.methods.GetBalance()
}

// RecaptchaV2 solves a recaptcha v2
func (s *Solver) RecaptchaV2(o RecaptchaV2Options) (*Solution, error) {
	if s.methods.RecaptchaV2 == nil {
		return nil, errors.New("service does not support recaptchaV2")
	}
	return s.methods.RecaptchaV2(o)
}

func (s *Solver) RecaptchaV3(o RecaptchaV3Options) (*Solution, error) {
	if s.methods.RecaptchaV3 == nil {
		return nil, errors.New("service does not support recaptchaV3")
	}
	return s.methods.RecaptchaV3(o)
}

func (s *Solver) HCaptcha(o HCaptchaOptions) (*Solution, error) {
	if s.methods.HCaptcha == nil {
		return nil, errors.New("service does not support hCaptcha")
	}
	return s.methods.HCaptcha(o)
}

func (s *Solver) FunCaptcha(o FunCaptchaOptions) (*Solution, error) {
	if s.methods.FunCaptcha == nil {
		return nil, errors.New("service does not support funCaptcha")
	}
	return s.methods.FunCaptcha(o)
}

func (s *Solver) Cloudflare(o CloudflareOptions) (*Solution, error) {
	if s.methods.Cloudflare == nil {
		return nil, errors.New("service does not support cloudflare")
	}
	return s.methods.Cloudflare(o)
}

// Kasada is only supported with capsolver.com
func (s *Solver) Kasada(o KasadaOptions) (*KasadaSolution, error) {
	if s.methods.Kasada == nil {
		return nil, errors.New("service does not support kasada")
	}
	return s.methods.Kasada(o)
}

// RecaptchaV3Options All fields are required
type RecaptchaV3Options struct {
	PageURL    string
	SiteKey    string
	Enterprise bool

	// MinScore should only be 0.3, 0.7, or 0.9
	MinScore float64

	// Action is the page_action in the requests
	Action string
}

type FunCaptchaOptions struct {
	PageURL   string
	PublicKey string

	// Subdomain also known as surl is optional
	Subdomain string

	// Proxy is optional but recommended
	Proxy *Proxy

	// UserAgent is required
	UserAgent string

	// Data is the extra data. Can look like: {"\blob\":\"HERE_COMES_THE_blob_VALUE\"}
	Data string
}

// KasadaOptions Make sure to set the proxy as its required
type KasadaOptions struct {
	PageURL string

	// Proxy is required
	Proxy *Proxy

	// DetailedCD Enable if you need more detailed x-kpsdk-cd, including params such as duration, st and rst
	DetailedCD bool

	// OnlyCD Enable if the solution contains only x-kpsdk-cd
	OnlyCD bool

	// Version Currently supports 2.0 and 3.0, default is 3.0
	Version string

	// UserAgent Browser's User-Agent which is used in emulation. Default is random
	UserAgent string
}

type HCaptchaOptions struct {
	PageURL           string
	SiteKey           string
	UserAgent         string
	Invisible         bool
	Proxy             *Proxy
	EnterprisePayload *HCaptchaEnterprise
}

// HCaptchaEnterprise Not every captcha service supports every field here
type HCaptchaEnterprise struct {
	RQData      string
	Sentry      bool
	APIEndpoint string
	Endpoint    string
	ReportAPI   string
	AssetHost   string
	ImgHost     string
}

type RecaptchaV2Options struct {
	// SiteKey is the site key of the recaptcha
	SiteKey string
	// PageURL is the URL of the page where the reCAPTCHA is located
	PageURL string
	// DataS is the data-s attribute of the reCAPTCHA element (optional)
	DataS string
	// Proxy is the proxy to use for the captcha (optional)
	Proxy *Proxy
	// UserAgent is the user agent to use for the captcha (optional)
	UserAgent string
	// Cookies is the cookies to use for the captcha (optional)
	Cookies map[string]string
	// Invisible is whether the captcha is invisible or not (optional)
	Invisible bool
	// Enterprise only works on some captcha services (optional)
	Enterprise map[string]interface{}
	// APIDomain is the domain of the recaptcha (optional)
	APIDomain string
}

// CloudflareOptions cloudflare challenges only work with capsolver.com, turnstile works with other solvers
type CloudflareOptions struct {
	PageURL string
	Proxy   *Proxy

	// SiteKey is only used for CloudflareTypeTurnstile
	SiteKey string

	// Type must only be CloudflareTypeTurnstile if the solver is not capsolver.com
	Type CloudflareType

	// Metadata will only be used on capsolver.com, for any other solver it will just append the fields
	Metadata map[string]string

	// Action and CData are only used for turnstile. CData is only used for 2captcha and capsolver.com
	Action string
	CData  string

	// HTML is only needed for cloudflare challenges
	HTML string
}

type Solution struct {
	Text string

	// TaskId is normally a int, but can be a string depending on the service
	TaskId any

	// RawSolution not supported on 2captcha methods
	RawSolution map[string]interface{}

	// Speed the time in milliseconds that the captcha took to solve
	Speed int64

	// Cookies can be nil or empty if the service does not return cookies
	Cookies map[string]string

	// Cost can be "" if the service does not return cost
	Cost string

	// IP can be "" if the service does not return IP
	IP string
}

type KasadaSolution struct {
	*Solution

	// KpsdkCT is the 'x-kpsdk-ct' header
	KpsdkCT string

	// KpsdkCD is the 'x-kpsdk-cd' header
	KpsdkCD string

	// UserAgent is the user agent used to solve the captcha
	UserAgent string
}

type CloudflareType int

const (
	CloudflareTypeTurnstile CloudflareType = iota
	CloudflareTypeChallenge
)
