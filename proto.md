### Service
```proto
// Простой унарный запрос (Unary RPC) Классический запрос-ответ. Клиент отправил один запрос — сервер вернул один ответ.
service Greeter {
  rpc SayHello (HelloRequest) returns (HelloReply);
}

// Серверный стриминг (Server Streaming) Клиент отправляет один запрос, а сервер в ответ открывает канал и присылает поток сообщений
service Greeter {
  // Обратите внимание на stream перед HelloReply
  rpc StreamHello (HelloRequest) returns (stream HelloReply);
}

// Клиентский стриминг (Client Streaming) Клиент открывает поток и отправляет множество сообщений (например, загрузка файла по частям), а сервер после получения всех данных отдает один итоговый ответ.
service Greeter {
  // stream перед HelloRequest
  rpc UploadLog (stream LogChunk) returns (UploadStatus);
}

// Двунаправленный стриминг (Bidirectional Streaming)
service Greeter {
  // stream с обеих сторон
  rpc LiveChat (stream ChatMessage) returns (stream ChatMessage);
}
```