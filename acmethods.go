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

	createTask := func(task map[string]interface{}) (any, error) {
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

		taskStr, ok := taskId.(string)
		if ok {
			return taskStr, nil
		}

		return int(taskId.(float64)), nil
	}

	// parseResponse returns should continue, solution, error
	parseResponse := func(body map[string]interface{}) (bool, *Solution, error) {
		errMsg, hasError := body["errorDescription"]
		if hasError && errMsg != nil {
			return false, nil, errors.New(errMsg.(string))
		}

		status := body["status"]

		switch status {
		case "processing":
			return true, nil, nil
		case "ready":
			solution, hasSolution := body["solution"].(map[string]interface{})
			if !hasSolution {
				return false, nil, errors.New("no solution")
			}

			// response can either be gRecaptchaResponse or token
			response := solution["gRecaptchaResponse"]

			if response == nil {
				response = solution["token"]
			}

			if response == nil {
				response = solution["x-kpsdk-cd"]
			}

			if response == nil {
				response = solution["x-kpsdk-ct"]
			}

			if response == nil {
				if solver.Verbose {
					fmt.Println(body)
				}

				return false, nil, errors.New("no solution text")
			}

			ip := ""
			cost := ""

			rIP, hasIP := body["ip"]
			if hasIP && rIP != nil {
				ip = rIP.(string)
			}

			rCost, hasCost := body["cost"]
			if hasCost && rCost != nil {
				cost = fmt.Sprintf("%v", rCost)
			}

			text, _ := response.(string)

			return false, &Solution{
				Text:        text,
				RawSolution: solution,
				IP:          ip,
				Cost:        cost,
			}, nil
		default:
			return false, nil, errors.New("unknown status")
		}
	}

	// keeps retrying until it has returned error or solved
	getResponse := func(taskId any) (*Solution, error) {
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

			shouldContinue, sol, err := parseResponse(body)
			if err != nil {
				return nil, err
			}

			if shouldContinue {
				continue
			}

			sol.TaskId = taskId
			return sol, nil
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

			if o.APIDomain != "" {
				taskData["apiDomain"] = o.APIDomain
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

			baseTask := "HCaptchaTask"

			// for capsolver.com HCaptchaTurboTask than the regular task is better, but requires proxy
			if solver.service == CapSolver && o.Proxy != nil {
				baseTask = "HCaptchaTurboTask"
			}

			applyProxy(taskData, o.Proxy, baseTask)

			if o.UserAgent != "" {
				taskData["userAgent"] = o.UserAgent
			}

			if o.EnterprisePayload != nil {
				ep := o.EnterprisePayload

				// some apis are slightly different
				if ep.RQData != "" {
					taskData["data"] = o.EnterprisePayload.RQData
				}

				payload := map[string]interface{}{}

				if ep.Sentry {
					payload["sentry"] = ep.Sentry
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
			if o.Proxy == nil {
				return nil, errors.New("proxy is required")
			}

			taskData := map[string]interface{}{
				"pageURL": o.PageURL,
				"cd":      o.DetailedCD,
				"onlyCD":  o.OnlyCD,
			}

			applyProxy(taskData, o.Proxy, "AntiKasadaTask")

			if o.Version != "" {
				taskData["version"] = o.Version
			}

			if o.UserAgent != "" {
				taskData["userAgent"] = o.UserAgent
			}

			// send request to /kasada/invoke
			payload := map[string]interface{}{
				"clientKey": solver.ApiKey,
				"task":      taskData,
				"appId":     "B7E57F27-0AD3-434D-A5B7-CF9EE7D093EF",
			}

			body, err := postJSON(domain()+"/kasada/invoke", payload)
			if err != nil {
				return nil, err
			}

			_, sol, err := parseResponse(body)
			if err != nil {
				return nil, err
			}

			if sol == nil {
				return nil, errors.New("no solution")
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

		methods.Cloudflare = func(o CloudflareOptions) (*Solution, error) {
			if o.Proxy == nil {
				return nil, errors.New("proxy is required")
			}

			if o.Metadata == nil {
				o.Metadata = map[string]string{}
			}

			// only set metadata type if one wasn't provided
			if _, ok := o.Metadata["type"]; !ok {
				switch o.Type {
				case CloudflareTypeChallenge:
					o.Metadata["type"] = "challenge"
				case CloudflareTypeTurnstile:
					o.Metadata["type"] = "turnstile"
				default:
					o.Metadata["type"] = ""
				}
			}

			if _, ok := o.Metadata["action"]; !ok && o.Action != "" {
				o.Metadata["action"] = o.Action
			}

			if _, ok := o.Metadata["cdata"]; !ok && o.CData != "" {
				o.Metadata["cdata"] = o.CData
			}

			taskData := map[string]interface{}{
				"websiteURL": o.PageURL,
				"metadata":   o.Metadata,
			}

			if o.SiteKey != "" {
				taskData["websiteKey"] = o.SiteKey
			}

			applyProxy(taskData, o.Proxy, "AntiCloudflareTask")

			return createResponse(taskData)
		}
	} else {
		methods.Cloudflare = func(o CloudflareOptions) (*Solution, error) {
			if o.Type == CloudflareTypeChallenge {
				return nil, errors.New("cloudflare challenge type is not supported by this solver")
			}

			taskData := map[string]interface{}{
				"websiteURL": o.PageURL,
				"websiteKey": o.SiteKey,
			}

			if o.Action != "" {
				taskData["action"] = o.Action
			}

			if o.Metadata != nil {
				for k, v := range o.Metadata {
					taskData[k] = v
				}
			}

			applyProxy(taskData, o.Proxy, "TurnstileTask")

			return createResponse(taskData)
		}
	}

	return methods
}
