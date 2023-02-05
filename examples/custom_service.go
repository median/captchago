package main

import (
	"fmt"
	"github.com/median/captchago"
)

func main() {
	// when setting captchago.AntiCaptcha as service, it will use the same API format as anti-captcha.com
	// but after setting a forced domain it will just replace anti-captcha.com with the domain you set
	solver, err := captchago.New(captchago.AntiCaptcha, "YOUR_API_KEY")
	if err != nil {
		panic(err)
	}

	solver.ForcedDomain = "http://custom-service.com"

	sol, err := solver.HCaptcha(captchago.HCaptchaOptions{
		PageURL: "https://www.hcaptcha.com/demo",
		SiteKey: "10000000-ffff-ffff-ffff-000000000001",
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(sol.Text)
	fmt.Println(fmt.Sprintf("Solved in %v ms", sol.Speed))
}
