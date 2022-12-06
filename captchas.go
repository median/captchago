package CaptchaGO

import (
	"errors"
)

type solveMethods struct {
	GetBalance  func() (float64, error)
	RecaptchaV2 func(RecaptchaV2Options) (*Solution, error)
	RecaptchaV3 func(RecaptchaV3Options) (*Solution, error)
	HCaptcha    func(HCaptchaOptions) (*Solution, error)
	FunCaptcha  func(FunCaptchaOptions) (*Solution, error)
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
}

type Solution struct {
	Text   string
	TaskId int

	// Speed the time in milliseconds that the captcha took to solve
	Speed int64

	// Cookies can be nil or empty if the service does not return cookies
	Cookies map[string]string

	// Cost can be "" if the service does not return cost
	Cost string

	// IP can be "" if the service does not return IP
	IP string
}
