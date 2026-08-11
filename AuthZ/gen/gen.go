// Package gen — точка входа кодогенерации. Собственного кода не содержит:
// здесь живёт только директива go:generate, а рядом, в подпакетах,
// лежит сгенерированный из .proto код.
//
// Регенерация: go generate ./...
package gen

//go:generate protoc -I ../api/proto --go_out=.. --go_opt=module=authz-example --go-grpc_out=.. --go-grpc_opt=module=authz-example ../api/proto/authz/v1/authz.proto
