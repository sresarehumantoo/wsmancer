BIN     := wsmancer

# Live-check target, for `make tickets` / `make verify` only. No default: these
# talk to a real box, and a stale hostname baked in here would mean running them
# against whatever now answers to it. Pass them on the command line,
#   make verify TARGET=dc01.corp.local DCIP=10.10.10.5
#, with the credentials in the environment (scripts/README.md has the list).
TARGET  ?=
DCIP    ?=

.PHONY: all build sealcheck test vet fmt check mutants tickets verify clean

all: check build

build:
	go build -o $(BIN) ./cmd/wsmancer

# sealcheck drives the ntlmseal/krbseal providers directly against a WinRM box;
# scripts/verify-matrix.sh runs it, so it stays buildable.
sealcheck:
	go build -o wsmancer-sealcheck ./cmd/sealcheck

test:
	go test ./internal/...
	# The fork's wsman package carries patches with their own tests (the
	# RelatesTo correlation check, the SOAP-fault summariser). CI runs these;
	# `make check` has to as well or a local pass means less than a CI pass.
	# It is a separate module whose go.mod replaces ../go-psrpcore with a
	# directory that does not exist here, so only the patched packages are
	# testable, same reasoning as the CI job.
	cd go-psrp-fork && go test ./wsman/...

vet:
	go vet ./cmd/... ./internal/...

fmt:
	gofmt -w cmd internal

check: test vet
	@test -z "$$(gofmt -l cmd internal)" || { echo "gofmt needed:"; gofmt -l cmd internal; exit 1; }

# Mutation differentials for the two sealing packages' unit tests. Both need no
# target, so they are CI-safe; kept out of `check` only because they rebuild the
# package once per mutant. Each fails unless every mutant is caught, the
# scripts are the counts, so this comment does not carry one to go stale.
#
# Both exist for the same structural reason and neither generalises to the rest
# of the repo: these are the only packages carrying crypto they implement
# themselves, where a wrong algorithm stays self-consistent across both ends of
# a session and so never surfaces as a visible failure. See each script's
# header, and the "Verifying against a live target" section of CONTRIBUTING.md.
mutants:
	./scripts/ntlmseal-mutants.sh
	./scripts/krbseal-mutants.sh

# Live checks; need a reachable target, credentials in the environment, and (for
# verify) the tickets `make tickets` mints. See scripts/README.md.
tickets:
	@test -n "$(DCIP)" || { echo "set DCIP=<dc-ip> (and TARGET, KRBUSER, KRBPASS, NT, AES)"; exit 1; }
	TARGET=$(TARGET) ./scripts/get-tickets.sh $(DCIP)

verify: sealcheck
	@test -n "$(TARGET)" -a -n "$(DCIP)" || { echo "set TARGET=<winrm-host> DCIP=<dc-ip>"; exit 1; }
	./scripts/verify-matrix.sh $(TARGET) $(DCIP)

clean:
	rm -f $(BIN) wsmancer-sealcheck
