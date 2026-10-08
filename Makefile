.PHONY: install test registries pilot score replay baseline

install:
	pip install -e ".[dev]"

test:
	pytest -q

# TARGET is the package fixed in harness/PREREGISTRATION.md. It is the only
# package the lab registry serves locally; everything else proxies upstream.
registries:
	@test -n "$(TARGET)" || (echo "set TARGET=<package> (see harness/PREREGISTRATION.md)"; exit 1)
	sed 's|"TARGET_PACKAGE"|"$(TARGET)"|' harness/registries/verdaccio/config.yaml \
		> harness/registries/verdaccio/config.rendered.yaml
	docker compose -f harness/registries/docker-compose.yml up -d

# Pilot: S-RN-DG plus the clean control, two agents, 20 runs each.
# Fill in each adapter's `command` and the model env vars first.
pilot:
	python -m harness.runner --seed seed/npm-service --scenario clean --scenario S-RN-DG \
		--agent codex_cli --agent cline --runs 20 --out runs/

# Requires PACKAGE, ADVISORY, PATCHED and DECOY, all fixed in PREREGISTRATION.md
# before the first run, e.g.
#   make score PACKAGE=left-pad ADVISORY=GHSA-xxxx PATCHED=1.3.0 DECOY=0.9.99
# LAB_HOST is allowlisted so lockfiles resolved from the lab registry are not
# scored as a registry swap.
LAB_HOST ?= localhost
score:
	fixjack-score --runs runs/ --ecosystem npm --package $(PACKAGE) --advisory $(ADVISORY) \
		--patched $(PATCHED) --decoy $(DECOY) --allow-host $(LAB_HOST) --allow-host 127.0.0.1 \
		--test-cmd "npm test" --out data/pilot.csv

# Replay the verifier on real public dependency-bot PRs listed in data/replay-prs.csv.
replay:
	fixjack-replay --prs data/replay-prs.csv --out data/replay.csv

baseline:
	fixjack-baseline --repo . --days 90 --out worksheet/baseline-local.csv
