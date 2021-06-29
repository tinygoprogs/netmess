BINS = tools/testing/sshcli tools/testing/sshsrv nmess sshmitm
RACE ?= 
build = build $(RACE)

tools:
	go $(build) tools/nmess.go
	go $(build) tools/sshmitm.go

tools/testing/sshcli: tools/testing/sshcli.go
	go $(build) -o $@ $<
tools/testing/sshsrv: tools/testing/sshsrv.go
	go $(build) -o $@ $<

testtools: tools/testing/sshcli tools/testing/sshsrv

.PHONY: tools clean test watchentropy fmt
clean:
	go clean
	rm -f $(BINS)

test: testtools
	cd mitm && go test $(RACE)

watchentropy:
	watch -n0.5 cat /proc/sys/kernel/random/entropy_avail

fmt:
	for d in discovery mitm spoof tools tools/testing tools/testing/util; \
		do ( cd $$d && go fmt; ); \
	done
