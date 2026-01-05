.PHONY: proto build run clean test

proto:
	protoc -I proto \
		--go_out=proto --go_opt=paths=source_relative \
		--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=proto --grpc-gateway_opt=paths=source_relative \
		proto/auth/auth.proto

build:
	go build -o bin/server cmd/server/main.go

run:
	go run cmd/server/main.go

clean:
	rm -rf bin/

test:
	go test ./...

deps:
	go mod download
	go mod tidy