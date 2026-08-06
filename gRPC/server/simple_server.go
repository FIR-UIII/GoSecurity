package main

import (
	"context"
	"fmt"
	pb "grpc-practice/proto"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
)

type server struct {
	// Embed the unimplemented server for forward compatibility
	pb.UnimplementedGreeterServer
}

// rpc call implementation
// SayHello is a simple RPC call that takes a HelloRequest and returns a HelloReply.
func (s *server) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	userID := md.Get("x-user-id")
	log.Printf("Received request with x-user-id: %s", userID)
	log.Printf("Received request with ID: %s", req.GetId())
	return &pb.HelloReply{Message: fmt.Sprintf("Hello, %s!", req.GetId())}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Create a new gRPC server
	s := grpc.NewServer()
	// Register the Greeter service with the gRPC server
	pb.RegisterGreeterServer(s, &server{})

	// add reflection service on gRPC server.
	reflection.Register(s)

	// Start the gRPC server
	log.Printf("gRPC server listening on %s", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
