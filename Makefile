.PHONY: help install server clickhouse clickhouse-prod clickhouse-stop clickhouse-postgres-remote postgres postgres-client postgres-prod postgres-stop

require = \
	  $(foreach 1,$1,$(__require))
__require = \
	    $(if $(value $1),, \
	    $(error Provide required parameter: $1$(if $(value 2), ($(strip $2)))))

help:
	@perl -nle'print $& if m{^[a-zA-Z_-]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install: ## Run the initial setup
	mix deps.get
	mix ecto.create
	mix ecto.migrate
	mix download_country_database
	npm install --prefix assets
	npm install --prefix tracker
	npm run deploy --prefix tracker

server: ## Start the web server
	mix phx.server

CH_FLAGS ?= --detach -p 8123:8123 -p 9000:9000 --ulimit nofile=262144:262144 --name plausible_clickhouse --env CLICKHOUSE_SKIP_USER_SETUP=1

clickhouse: ## Start a container with a recent version of clickhouse
	docker run $(CH_FLAGS) --network host --volume=$$PWD/.clickhouse_db_vol:/var/lib/clickhouse --volume=$$PWD/.clickhouse_config:/etc/clickhouse-server/config.d clickhouse/clickhouse-server:latest-alpine

clickhouse-client: ## Connect to clickhouse
	docker exec -it plausible_clickhouse clickhouse-client -d plausible_events_db

clickhouse-prod: ## Start a container with the same version of clickhouse as the one in prod
	docker run $(CH_FLAGS) --volume=$$PWD/.clickhouse_db_vol_prod:/var/lib/clickhouse clickhouse/clickhouse-server:25.11.5.8-alpine

clickhouse-stop: ## Stop and remove the clickhouse container
	docker stop plausible_clickhouse && docker rm plausible_clickhouse

clickhouse-postgres-remote: ## Create postgres_remote database in ClickHouse for querying PostgreSQL
	$(eval POSTGRES_IP := $(shell docker inspect plausible_db --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'))
	@docker exec plausible_clickhouse clickhouse-client --query "DROP DATABASE IF EXISTS postgres_remote; CREATE DATABASE postgres_remote ENGINE = PostgreSQL('$(POSTGRES_IP):5432', 'plausible_dev', 'postgres', 'postgres');"

PG_FLAGS ?= --detach -e POSTGRES_PASSWORD="postgres" -p 5432:5432 --name plausible_db

postgres: ## Start a container with a recent version of postgres
	docker run $(PG_FLAGS) --volume=plausible_db:/var/lib/postgresql/docker postgres:latest

postgres-client: ## Connect to postgres
	docker exec -it plausible_db psql -U postgres -d plausible_dev

postgres-prod: ## Start a container with the same version of postgres as the one in prod
	docker run $(PG_FLAGS) --volume=plausible_db_prod:/var/lib/postgresql/docker postgres:18

postgres-stop: ## Stop and remove the postgres container
	docker stop plausible_db && docker rm plausible_db

browserless:
	docker run -e "TOKEN=dummy_token" -p 3000:3000 --network host ghcr.io/browserless/chromium

minio: ## Start a transient container with a recent version of minio (s3)
	docker run -d --rm -p 10000:10000 -p 10001:10001 --name plausible_minio minio/minio server /data --address ":10000" --console-address ":10001"
	while ! docker exec plausible_minio mc alias set local http://localhost:10000 minioadmin minioadmin; do sleep 1; done
	docker exec plausible_minio sh -c 'mc mb local/dev-exports && mc ilm add --expiry-days 7 local/dev-exports'
	docker exec plausible_minio sh -c 'mc mb local/dev-imports && mc ilm add --expiry-days 7 local/dev-imports'
	docker exec plausible_minio sh -c 'mc mb local/test-exports && mc ilm add --expiry-days 7 local/test-exports'
	docker exec plausible_minio sh -c 'mc mb local/test-imports && mc ilm add --expiry-days 7 local/test-imports'

minio-stop: ## Stop and remove the minio container
	docker stop plausible_minio

sso-stop:
	docker stop idp
	docker remove idp

loadtest-server:
	@echo "Ensure your OTP installation is built with --enable-lock-counter"
	MIX_ENV=load ERL_FLAGS="-emu_type lcnt +Mdai max" iex -S mix do phx.digest + phx.server

loadtest-client:
	@echo "Set your limits for file descriptors/ephemeral ports high... Test begins shortly"
	@sleep 5
	k6 run test/load/script.js  
