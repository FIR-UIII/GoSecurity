### Путаница номеров полей (Field Tag Confusion)
Protobuf сериализует данные, опираясь только на номера полей (теги), а не на их названия. Если вы переиспользуете номер удаленного поля, старые клиенты и новые серверы перестанут понимать друг друга, что может привести к изменению прав или порче данных.

```proto1
message UpdateProfileRequest {
  string user_id = 1;
  bool is_admin = 2; // Тег 2 используется для флага администратора
}
```

```proto2
message UpdateProfileRequest {
  string user_id = 1;
  // ОШИБКА: Переиспользование тега 2
  string new_password = 2; 
}
```

Как исправить
```proto
message UpdateProfileRequest {
  string user_id = 1;
  
  // Резервируем тег и имя старого поля, чтобы никто их не занял
  reserved 2;
  reserved "is_admin";
  
  string new_password = 3; // Новое поле получает новый тег
}
```

### Утечка данных (Information Disclosure)
```proto
// ОШИБКА: Модель смешивает публичные и приватные данные
message User {
  string id = 1;
  string username = 2;
  string password_hash = 3; // Скрытое поле
  string internal_role = 4; // Скрытое поле
}

message GetUserResponse {
  User user = 1;
}
```

```go
func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
    var dbUser models.User
    // Достаем пользователя из базы данных
    s.db.First(&dbUser, "id = ?", req.Id)

    // Уязвимость: мы отдаем весь объект со всеми полями клиенту
    return &pb.GetUserResponse{
        User: &pb.User{
            Id:           dbUser.ID,
            Username:     dbUser.Username,
            PasswordHash: dbUser.PasswordHash, // Утечка хэша пароля!
            InternalRole: dbUser.InternalRole, // Утечка внутренней роли!
        },
    }, nil
}
```


### Векторы для DoS (Отказ в обслуживании)
```proto
Protocol Buffers
message BatchInsertRequest {
  // ОШИБКА: Нет ограничений на количество элементов
  repeated string massive_payload = 1; 
}
```

```go
func (s *server) BatchInsert(ctx context.Context, req *pb.BatchInsertRequest) (*pb.BatchInsertResponse, error) {
    // Уязвимость: выделение памяти, контролируемое пользователем
    results := make([]string, 0, len(req.MassivePayload)) 
    
    // Если req.MassivePayload содержит 10 миллионов записей, 
    // цикл загрузит процессор на 100% и исчерпает оперативную память (OOM).
    for _, item := range req.MassivePayload {
        processed := heavyProcessing(item)
        results = append(results, processed)
    }
    
    return &pb.BatchInsertResponse{}, nil
}
```

### DoS через тип RPC (Streaming DoS)
В чем уязвимость: Protobuf пытается десериализовать весь bytes file_content целиком в оперативную память перед передачей в обработчик Go. Если злоумышленник отправит файл размером 2 ГБ, gRPC-сервер попытается выгрузить эти 2 ГБ в RAM до выполнения первой строчки вашего кода. Несколько таких параллельных запросов мгновенно вызовут OOM (Out of Memory) и уронят сервис.
```proto
service FileService {
  // ОШИБКА: Загрузка через унарный метод вместо стрима
  rpc UploadBigFile (UploadRequest) returns (UploadResponse);
}

message UploadRequest {
  bytes file_content = 1; // Опасность!
}
```

```proto_safe
service FileService {
  // Safe: Использовать клиентский поток для передачи файлов частями
  rpc UploadBigFile (stream UploadChunk) returns (UploadResponse);
}

message UploadRequest {
  bytes file_content = 1; // Опасность!
}
```

### Избыточность интерфейса (Over-Exposed Interface)
В чем уязвимость: Если вы используете gRPC-Gateway (для превращения gRPC в REST) или единый API Gateway, все методы из блока service автоматически становятся доступны снаружи. Если разработчик на Go забудет повесить авторизационный middleware на метод DebugDumpDatabase, любой внешний пользователь сможет его вызвать.
Как исправить: Разделять методы на разные service по уровню доступа (например, PublicUserService и InternalAdminService) и не выставлять внутренние сервисы на внешние порты/гейтвеи.

```proto
service AdminUserService {
  // Публичные методы для всех
  rpc GetProfile (ProfileRequest) returns (ProfileResponse);
  
  // ОШИБКА: Служебные/отладочные методы объявлены в том же сервисе
  rpc DebugDumpDatabase (Empty) returns (stream DbRow);
  rpc HardResetUserPassword (ResetRequest) returns (Empty);
}
```