package CaptchaGO

import (
	"errors"
	"strings"
	"time"
)

const (
	AntiCaptcha SolveService = "anticaptcha"
	AnyCaptcha  SolveService = "anycaptcha"
	CapSolver   SolveService = "capsolver"
	TwoCaptcha  SolveService = "2captcha"
	CapMonster  SolveService = "capmonster"
)

func New(service SolveService, apiKey string) (*Solver, error) {
	solver := &Solver{
		Verbose:     true,
		ApiKey:      apiKey,
		UpdateDelay: time.Second * 2,
	}

	err := solver.SetService(service)
	if err != nil {
		return nil, err
	}

	return solver, nil
}

func (s *Solver) SetService(service SolveService) error {
	service = formatService(service)

	switch service {
	case AntiCaptcha:
		s.methods = antiCaptchaMethods(s, "api.anti-captcha.com")
		break
	case AnyCaptcha:
		s.methods = antiCaptchaMethods(s, "api.anycaptcha.com")
		break
	case CapMonster:
		s.methods = antiCaptchaMethods(s, "api.capmonster.cloud")
		break
	case CapSolver:
		s.methods = antiCaptchaMethods(s, "api.capsolver.com")
		break
	case TwoCaptcha:
		s.methods = twoCaptchaMethods(s, "2captcha.com")
	default:
		return errors.New("that service isn't supported")
	}

	s.service = service
	return nil
}

func (s *Solver) GetService() SolveService {
	return s.service
}

// formatService formats the service name to reduce the chance of human errors
func formatService(s SolveService) SolveService {
	s = strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), " ", ""), "-", "")

	// rucaptcha uses same api as 2captcha, its just different name
	if s == "rucaptcha" {
		return "2captcha"
	}

	return s
}

type Solver struct {
	// UpdateDelay is the delay between each update getTaskResult request
	UpdateDelay time.Duration

	// Disabling Verbose will disable all logging
	Verbose bool

	// ApiKey is the key used to authenticate with the service
	ApiKey string

	// ForcedDomain don't edit unless you know what you're doing.
	// This is used to allow the user to change their captcha service to whatever
	// they want as long as they share the same api methods.
	ForcedDomain string

	// service is the service that the solver is using. It's private because it's only used internally
	service SolveService

	// methods is the methods used to solve captchas. It's private because it's only used internally
	methods *solveMethods
}

type SolveService = string
