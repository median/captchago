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

	sol, err := solver.Cloudflare(captchago.CloudflareOptions{
		PageURL: "https://demo.turnstile.workers.dev/",
		SiteKey: "1x00000000000000000000AA",
		Type:    captchago.CloudflareTypeTurnstile,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(sol.Text)
	fmt.Println(fmt.Sprintf("Solved in %v ms", sol.Speed))
}
