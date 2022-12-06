package CaptchaGO

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

func cookiesToString(input map[string]string) string {
	var output string

	for k, v := range input {
		output += k + "=" + v + "; "
	}

	if len(output) > 0 {
		output = output[:len(output)-2]
	}

	return output
}

func postJSON(url string, data map[string]interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var output map[string]interface{}

	err = json.Unmarshal(body, &output)
	if err != nil {
		return nil, err
	}

	return output, err
}

func postQuery(link string, data map[string]interface{}) (string, error) {
	var querys string

	if data != nil {
		for k, v := range data {
			str := ""

			switch v.(type) {
			case string:
				str = v.(string)
				break
			case int:
				str = strconv.Itoa(v.(int))
				break
			case float64:
				str = fmt.Sprintf("%.3f", v.(float64))
				break
			}

			querys += url.QueryEscape(k) + "=" + url.QueryEscape(str) + "&"
		}

		if len(querys) > 0 {
			querys = "?" + querys[:len(querys)-1]
		}
	}

	resp, err := http.Get(link + querys)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
