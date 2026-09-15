package auth

import (
	"context"
	"log"
	"github.com/redis/go-redis/v9"
)

const PolicyReloadChannel = "casbin.policy.reload"

func StartReloadListener(
	ctx context.Context,
	redisClient *redis.Client,
	enforcer *Enforcer,
) {

	pubsub := redisClient.Subscribe(
		ctx,
		PolicyReloadChannel,
	)

	go func() {
		defer pubsub.Close()

		if _, err := pubsub.Receive(ctx); err != nil {
			log.Printf(
				"redis reload subscription failed: %v",
				err,
			)

			return
		}

		log.Println(
			"subscribed to policy reload signal",
		)

		for {
			select {
			case <-ctx.Done():
				return

			case message, ok := <-pubsub.Channel():
				if !ok {
					return
				}

				log.Printf(
					"policy reload signal received: %s",
					message.Payload,
				)

				if err := enforcer.LoadPolicy(); err != nil {
					log.Printf(
						"casbin LoadPolicy failed: %v",
						err,
					)

					continue
				}

				log.Println(
					"casbin policy reloaded",
				)
			}
		}
	}()
}