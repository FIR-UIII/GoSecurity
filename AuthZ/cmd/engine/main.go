package main

import (
	pb "authz-example/gen/authz/v1"
	"context"
	"log/slog"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type server struct {
	// Embed the unimplemented server for forward compatibility
	pb.UnimplementedAuthorizationServiceServer
}

func (s *server) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	if req.Action == "read" {
		return &pb.CheckResponse{
			Allowed: true,
		}, nil
	}
	return &pb.CheckResponse{
		Allowed: false,
	}, nil
}

func main() {
	// Create a new gRPC server
	s := grpc.NewServer()
	reflection.Register(s)
	// Register the Authorization service with the gRPC server
	pb.RegisterAuthorizationServiceServer(s, &server{})
	slog.Info("gRPC server listening on :50051")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		slog.Error("failed to listen", "error", err)
		return
	}
	if err := s.Serve(lis); err != nil {
		slog.Error("failed to serve", "error", err)
	}
}
