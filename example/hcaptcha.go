package main

import (
	"fmt"
	"github.com/median/captchago"
)

func main() {
	solver, err := captchago.New(captchago.AntiCaptcha, "YOUR_API_KEY")
	if err != nil {
		panic(err)
	}

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
