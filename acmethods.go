package captchago

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

func antiCaptchaMethods(solver *Solver, preferredDomain string) *solveMethods {
	domain := func() string {
		r := preferredDomain
		if solver.ForcedDomain != "" {
			r = solver.ForcedDomain
		}

		if !strings.Contains(r, "://") {
			// detects if it's an ip or a domain
			if strings.Contains(r, ":") || strings.Count(r, ".") == 4 {
				r = "http://" + r
			} else {
				r = "https://" + r
			}
		}

		return r
	}

	createTask := func(task map[string]interface{}) (int, error) {
		d := domain()

		payload := map[string]interface{}{
			"clientKey": solver.ApiKey,
			"task":      task,
		}

		if strings.Contains(d, "anti-captcha.com") {
			payload["softId"] = 1080
		} else if strings.Contains(d, "capmonster.cloud") {
			payload["softId"] = 59
		} else if strings.Contains(d, "capsolver.com") {
			payload["appId"] = "B7E57F27-0AD3-434D-A5B7-CF9EE7D093EF"
		}

		body, err := postJSON(d+"/createTask", payload)
		if err != nil {
			return 0, err
		}

		createErr, hasError := body["errorDescription"]
		if hasError && createErr != nil {
			return 0, errors.New(createErr.(string))
		}

		taskId, hasTaskId := body["taskId"]
		if !hasTaskId {
			return 0, errors.New("no taskId")
		}

		return int(taskId.(float64)), nil
	}

	// keeps retrying until it has returned error or solved
	getResponse := func(taskId int) (*Solution, error) {
		for {
			time.Sleep(solver.UpdateDelay)

			if solver.Verbose {
				fmt.Println("getting response for task", taskId)
			}

			d := domain()

			payload := map[string]interface{}{
				"clientKey": solver.ApiKey,
				"taskId":    taskId,
			}

			body, err := postJSON(d+"/getTaskResult", payload)
			if err != nil {
				if solver.Verbose {
					_ = fmt.Errorf("error while getting task result: %s\n", err)
				}
				continue
			}

			errMsg, hasError := body["errorDescription"]
			if hasError && errMsg != nil {
				return nil, errors.New(errMsg.(string))
			}

			status := body["status"]

			switch status {
			case "processing":
				continue
			case "ready":
				solution, hasSolution := body["solution"].(map[string]interface{})
				if !hasSolution {
					return nil, errors.New("no solution")
				}

				// response can either be gRecaptchaResponse or token
				response := solution["gRecaptchaResponse"]

				if response == nil {
					response = solution["token"]
				}

				if response == nil {
					response = solution["x-kpsdk-ct"]
				}

				if response == nil {
					if solver.Verbose {
						fmt.Println(body)
					}

					return nil, errors.New("no solution text")
				}

				ip := ""
				cost := ""

				rIP, hasIP := body["ip"]
				if hasIP && rIP != nil {
					ip = rIP.(string)
				}

				rCost, hasCost := body["cost"]
				if hasCost && rCost != nil {
					cost = rCost.(string)
				}

				return &Solution{
					TaskId:      taskId,
					Text:        response.(string),
					RawSolution: solution,
					IP:          ip,
					Cost:        cost,
				}, nil
			default:
				return nil, errors.New("unknown status")
			}
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

	applyProxy := func(data map[string]interface{}, p *Proxy, taskName string) {
		if p == nil {
			data["type"] = taskName + "Proxyless"
			return
		}

		data["type"] = taskName

		data["proxyAddress"] = p.address
		data["proxyPort"] = p.port
		if p.login != nil {
			data["proxyLogin"] = p.login.Username
			data["proxyPassword"] = p.login.Password
		}

		t := p.pType
		if t == ProxyTypeHTTPS {
			t = ProxyTypeHTTP
		}
		data["proxyType"] = t
	}

	methods := &solveMethods{
		GetBalance: func() (float64, error) {
			d := domain()

			payload := map[string]interface{}{
				"clientKey": solver.ApiKey,
			}

			body, err := postJSON(d+"/getBalance", payload)
			if err != nil {
				return 0, err
			}

			errMsg, hasError := body["errorDescription"]
			if hasError && errMsg != nil {
				return 0, errors.New(errMsg.(string))
			}

			balance, hasBalance := body["balance"]
			if !hasBalance {
				return 0, errors.New("no balance")
			}

			return balance.(float64), nil
		},
		RecaptchaV2: func(o RecaptchaV2Options) (*Solution, error) {
			taskData := map[string]interface{}{
				"websiteURL":  o.PageURL,
				"websiteKey":  o.SiteKey,
				"isInvisible": o.Invisible,
			}

			if o.Enterprise != nil {
				applyProxy(taskData, o.Proxy, "RecaptchaV2EnterpriseTask")
				taskData["enterprisePayload"] = o.Enterprise
			} else {
				applyProxy(taskData, o.Proxy, "RecaptchaV2Task")
			}

			if o.UserAgent != "" {
				taskData["userAgent"] = o.UserAgent
			}

			if o.Cookies != nil && len(o.Cookies) > 0 {
				taskData["cookies"] = cookiesToString(o.Cookies)
			}

			if o.DataS != "" {
				taskData["recaptchaDataSValue"] = o.DataS
			}

			return createResponse(taskData)
		},
		HCaptcha: func(o HCaptchaOptions) (*Solution, error) {
			taskData := map[string]interface{}{
				"websiteURL":  o.PageURL,
				"websiteKey":  o.SiteKey,
				"isInvisible": o.Invisible,
			}

			applyProxy(taskData, o.Proxy, "HCaptchaTask")

			if o.UserAgent != "" {
				taskData["userAgent"] = o.UserAgent
			}

			if o.EnterprisePayload != nil {
				// some apis are slightly different
				if o.EnterprisePayload.RQData != "" {
					taskData["data"] = o.EnterprisePayload.RQData
				}

				ep := o.EnterprisePayload

				payload := map[string]interface{}{
					"sentry": ep.Sentry,
				}

				if ep.RQData != "" {
					payload["rqdata"] = ep.RQData
				}

				if ep.APIEndpoint != "" {
					payload["apiEndpoint"] = ep.APIEndpoint
				}

				if ep.Endpoint != "" {
					payload["endpoint"] = ep.APIEndpoint
				}

				if ep.ReportAPI != "" {
					payload["reportapi"] = ep.ReportAPI
				}

				if ep.AssetHost != "" {
					payload["assethost"] = ep.AssetHost
				}

				if ep.ImgHost != "" {
					payload["imghost"] = ep.ImgHost
				}

				taskData["enterprisePayload"] = payload

			}

			return createResponse(taskData)
		},
		FunCaptcha: func(o FunCaptchaOptions) (*Solution, error) {
			taskData := map[string]interface{}{
				"websiteURL":               o.PageURL,
				"websitePublicKey":         o.PublicKey,
				"funcaptchaApiJSSubdomain": o.Subdomain,
			}

			applyProxy(taskData, o.Proxy, "FunCaptchaTask")

			taskData["userAgent"] = o.UserAgent

			return createResponse(taskData)
		},
		RecaptchaV3: func(o RecaptchaV3Options) (*Solution, error) {
			taskData := map[string]interface{}{
				"type":         "RecaptchaV3TaskProxyless",
				"websiteURL":   o.PageURL,
				"websiteKey":   o.SiteKey,
				"minScore":     o.MinScore,
				"pageAction":   o.Action,
				"isEnterprise": o.Enterprise,
			}

			return createResponse(taskData)
		},
	}

	// kasada method
	if solver.service == CapSolver {
		methods.Kasada = func(o KasadaOptions) (*KasadaSolution, error) {
			taskData := map[string]interface{}{
				"type":      "AntiKasadaTask",
				"pageURL":   o.PageURL,
				"cd":        o.DetailedCD,
				"onlyCD":    o.OnlyCD,
				"version":   o.Version,
				"userAgent": o.UserAgent,
			}

			if o.Proxy != nil {
				taskData["proxy"] = o.Proxy.String()
			}

			sol, err := createResponse(taskData)
			if err != nil {
				return nil, err
			}

			kpsdkCD := ""
			kpsdkCT := ""
			userAgent := ""

			raw := sol.RawSolution["x-kpsdk-cd"]
			if raw != nil {
				kpsdkCD = raw.(string)
			}

			raw = sol.RawSolution["x-kpsdk-ct"]
			if raw != nil {
				kpsdkCT = raw.(string)
			}

			raw = sol.RawSolution["user-agent"]
			if raw != nil {
				userAgent = raw.(string)
			}

			return &KasadaSolution{
				Solution:  sol,
				KpsdkCD:   kpsdkCD,
				KpsdkCT:   kpsdkCT,
				UserAgent: userAgent,
			}, nil
		}
	}

	return methods
}
