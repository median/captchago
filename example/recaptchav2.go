package main

import (
	"fmt"
	"github.com/median/captchago"
)

func main() {
	solver, err := captchago.New(captchago.CapMonster, "YOUR_API_KEY")
	if err != nil {
		panic(err)
	}

	sol, err := solver.RecaptchaV2(captchago.RecaptchaV2Options{
		PageURL: "https://www.google.com/recaptcha/api2/demo",
		SiteKey: "6LcZzrQUAAAAAER9Z9ZqZ6Z1Z6Z1Z6Z1Z6Z1Z6Z1",
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(sol.Text)
	fmt.Println(fmt.Sprintf("Solved in %v ms", sol.Speed))
}
