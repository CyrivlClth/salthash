export GOPROXY=https://goproxy.cn

.PHONY: vendor

vendor:
	go mod vendor