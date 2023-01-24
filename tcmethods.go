package captchago

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func twoCaptchaMethods(solver *Solver, preferredDomain string) *solveMethods {
	domain := func() string {
		r := preferredDomain
		if solver.ForcedDomain != "" {
			r = solver.ForcedDomain
		}

		if strings.Contains(r, ":") || strings.Count(r, ".") == 4 {
			r = "http://" + r
		} else {
			r = "https://" + r
		}

		return r
	}

	createTask := func(base map[string]interface{}) (int, error) {
		d := domain()

		base["key"] = solver.ApiKey
		base["soft_id"] = 3413

		body, err := postQuery(d+"/in.php", base)
		if err != nil {
			return 0, err
		}

		if !strings.Contains(body, "|") {
			return 0, errors.New(body)
		}

		taskId, err := strconv.Atoi(strings.Split(body, "|")[1])
		if err != nil {
			return 0, err
		}

		return taskId, nil
	}

	getResponse := func(taskId int) (*Solution, error) {
		for {
			time.Sleep(solver.UpdateDelay)

			if solver.Verbose {
				fmt.Println("getting response for task", taskId)
			}

			body, err := postQuery(domain()+"/res.php", map[string]interface{}{
				"key":    solver.ApiKey,
				"action": "get",
				"id":     taskId,
			})
			if err != nil {
				return nil, err
			}

			if strings.Contains(body, "CAPCHA_NOT_READY") {
				continue
			}

			if !strings.Contains(body, "OK|") {
				return nil, errors.New(body)
			}

			return &Solution{
				Text:   strings.TrimPrefix(body, "OK|"),
				TaskId: taskId,
			}, nil
		}
	}

	createResponse := func(taskData map[string]interface{}) (*Solution, error) {
		start := time.Now().UnixMilli()
		taskId, err := createTask(taskData)
		if err != nil {
			return nil, err
		}

		if solver.Verbose {
			fmt.Printf("created task with id %v\n", taskId)
		}

		sol, err := getResponse(taskId)
		if sol != nil {
			sol.Speed = time.Now().UnixMilli() - start
		}

		if solver.Verbose && err == nil {
			fmt.Printf("solved task with id %v\n", taskId)
		}

		return sol, err
	}

	return &solveMethods{
		GetBalance: func() (float64, error) {
			d := domain()

			body, err := postQuery(d+"/res.php", map[string]interface{}{
				"key":    solver.ApiKey,
				"action": "getbalance",
			})
			if err != nil {
				return 0, err
			}

			parsed, err := strconv.ParseFloat(body, 64)
			if err != nil {
				return 0, errors.New(body)
			}

			return parsed, nil
		},
		RecaptchaV2: func(o RecaptchaV2Options) (*Solution, error) {
			payload := map[string]interface{}{
				"method":    "userrecaptcha",
				"googlekey": o.SiteKey,
				"pageurl":   o.PageURL,
			}

			if o.Invisible {
				payload["invisible"] = 1
			}

			if o.DataS != "" {
				payload["data-s"] = o.DataS
			}

			if o.Cookies != nil && len(o.Cookies) > 0 {
				payload["cookies"] = cookiesToString(o.Cookies)
			}

			if o.UserAgent != "" {
				payload["userAgent"] = o.UserAgent
			}

			if o.Proxy != nil {
				payload["proxy"] = o.Proxy.String()
				payload["proxytype"] = strings.ToUpper(o.Proxy.pType)
			}

			return createResponse(payload)
		},
		HCaptcha: func(o HCaptchaOptions) (*Solution, error) {
			payload := map[string]interface{}{
				"method":  "hcaptcha",
				"sitekey": o.SiteKey,
				"pageurl": o.PageURL,
			}

			if o.Invisible {
				payload["invisible"] = 1
			}

			if o.UserAgent != "" {
				payload["userAgent"] = o.UserAgent
			}

			if o.Proxy != nil {
				payload["proxy"] = o.Proxy.String()
				payload["proxytype"] = strings.ToUpper(o.Proxy.pType)
			}

			if o.EnterprisePayload != nil && o.EnterprisePayload.RQData != "" {
				payload["data"] = o.EnterprisePayload.RQData
			}

			return createResponse(payload)
		},
		FunCaptcha: func(o FunCaptchaOptions) (*Solution, error) {
			payload := map[string]interface{}{
				"method":    "funcaptcha",
				"publickey": o.PublicKey,
				"pageurl":   o.PageURL,
			}

			if o.Subdomain != "" {
				payload["surl"] = o.Subdomain
			}

			if o.UserAgent != "" {
				payload["userAgent"] = o.UserAgent
			}

			if o.Proxy != nil {
				payload["proxy"] = o.Proxy.String()
				payload["proxytype"] = strings.ToUpper(o.Proxy.pType)
			}

			return createResponse(payload)
		},
		RecaptchaV3: func(o RecaptchaV3Options) (*Solution, error) {
			payload := map[string]interface{}{
				"method":    "userrecaptcha",
				"version":   "v3",
				"googlekey": o.SiteKey,
				"pageurl":   o.PageURL,
			}

			if o.Action != "" {
				payload["action"] = o.Action
			}

			if o.MinScore != 0 {
				payload["min_score"] = o.MinScore
			}

			if o.Enterprise {
				payload["enterprise"] = 1
			}

			return createResponse(payload)
		},
	}
}
