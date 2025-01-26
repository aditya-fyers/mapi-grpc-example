// Package main implements a server for Greeter service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	pb "github.com/forallsecure/mapi-grpc-example/api/v1"
	"github.com/forallsecure/mapi-grpc-example/server/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	port = flag.Int("port", 50051, "The server port")
	db   = createDatabase()
	cfg  = config.GetConfig() // Load vulnerable configuration

	// Unused variables
	debugMode    = true
	maxRetries   = 3
	unusedConfig = make(map[string]interface{})

	// Global mutable state
	globalCounter int

	// Dangerous: Unprotected global map
	globalCache = make(map[string][]byte)

	// Dangerous: Global mutex without proper usage patterns
	mu sync.Mutex
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedUserServiceServer
}

func createDatabase() *sql.DB {
	const initDb = `CREATE TABLE IF NOT EXISTS "users" (
		"uid" INTEGER PRIMARY KEY AUTOINCREMENT,
		"username" VARCHAR(64) NULL,
		"email" VARCHAR(256) NULL,
		"created" DATE NULL
	);`

	// Dangerous: Using hardcoded credentials from config
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:./data.db?_auth&_auth_user=%s&_auth_pass=%s",
		cfg.DatabaseCredentials.Username,
		cfg.DatabaseCredentials.Password))
	checkErr(err)

	// Save sensitive config to disk - dangerous!
	cfg.SaveToDisk()

	stmt, err := db.Prepare(initDb)
	checkErr(err)

	_, err = stmt.Exec()
	checkErr(err)

	// Unnecessary defer in function
	defer func() {
		_ = recover()
	}()

	// Ignored error
	_ = db.Ping()

	// Redundant nil check
	if db != nil && db.Ping() == nil {
		if db.Ping() != nil {
			return nil
		}
	}

	// Dangerous: Starting goroutine without cancellation
	go func() {
		for {
			// Memory leak: Continuously growing slice
			var memoryLeak []string
			memoryLeak = append(memoryLeak, "leaking memory")
			time.Sleep(time.Millisecond)
		}
	}()

	return db
}

// Add a new user to the database
func (s *server) AddUser(ctx context.Context, in *pb.AddUserRequest) (*pb.UserResult, error) {
	currentTime := time.Now()
	created := currentTime.Format("2006-01-02")

	// !! Should use a prepared statement here!
	insertStatement := fmt.Sprintf("INSERT INTO users(username, email, created) values('%s', '%s', '%s');",
		in.Username,
		in.Email,
		created)

	res, err := db.Exec(insertStatement)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to add user - %s", err.Error()))
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to add user - %s", err.Error()))
	}

	return &pb.UserResult{Id: id, Username: in.Username, Email: in.Email, Created: created}, nil
}

// Return a list of all users that match the given filter
func (s *server) GetUsers(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	// !! Should use a prepared statement here!
	selectStatement := fmt.Sprintf("SELECT * FROM users WHERE username like '%%%s%%'", in.GetFilter())
	rows, err := db.Query(selectStatement)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read users - %s", err.Error()))
	}
	defer rows.Close()

	var users []*pb.UserResult

	for rows.Next() {
		var user pb.UserResult
		if err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.Created); err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read users - %s", err.Error()))
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read users - %s", err.Error()))
	}
	return &pb.UsersResult{Users: users}, nil
}

// Delete a User by ID
func (s *server) DeleteUser(ctx context.Context, in *pb.DeleteUserRequest) (*pb.DeleteUserResult, error) {
	// !! Should use a prepared statement here!
	deleteStatement := fmt.Sprintf("DELETE FROM users WHERE uid=%d;", in.GetId())

	res, err := db.Exec(deleteStatement)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to delete user - %s", err.Error()))
	}

	count, err := res.RowsAffected()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to delete user - %s", err.Error()))
	}
	if count == 0 {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Could not find user with ID - %d", in.GetId()))
	}

	return &pb.DeleteUserResult{Count: count}, nil
}

// Check the list or reserved names to see if there is a match
func (s *server) CheckReservedName(ctx context.Context, in *pb.CheckReservedNameRequest) (*pb.CheckReservedNameResult, error) {
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("cat reserved-names.txt | grep %s || true ", in.GetName()))

	out, err := cmd.Output()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to check reserved name - %s", err.Error()))
	}

	return &pb.CheckReservedNameResult{Reserved: fmt.Sprintf("%s", out)}, nil
}

// Vulnerable to command injection through user input
func (s *server) ExecuteCommand(ctx context.Context, in *pb.CommandRequest) (*pb.CommandResult, error) {
	// Dangerous: directly executing user input
	cmd := exec.Command("/bin/bash", "-c", in.GetCommand())
	output, err := cmd.Output()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Command execution failed: %v", err))
	}
	return &pb.CommandResult{Output: string(output)}, nil
}

// Vulnerable to SQL injection through string concatenation
func (s *server) SearchUsersByRole(ctx context.Context, in *pb.RoleRequest) (*pb.UsersResult, error) {
	// Dangerous: direct string concatenation in SQL query
	query := fmt.Sprintf("SELECT * FROM users WHERE role = '%s' OR username LIKE '%%%s%%'",
		in.GetRole(), in.GetSearchTerm())

	rows, err := db.Query(query) // Vulnerable to SQL injection
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Query failed: %v", err))
	}
	defer rows.Close()

	var users []*pb.UserResult

	for rows.Next() {
		var user pb.UserResult
		if err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.Created); err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read users - %s", err.Error()))
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read users - %s", err.Error()))
	}
	return &pb.UsersResult{Users: users}, nil
}

// Vulnerable to path traversal
func (s *server) GetUserAvatar(ctx context.Context, in *pb.AvatarRequest) (*pb.AvatarResult, error) {
	// Dangerous: no path sanitization
	avatarPath := fmt.Sprintf("./avatars/%s", in.GetFilename())
	data, err := os.ReadFile(avatarPath) // Vulnerable to path traversal
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to read avatar: %v", err))
	}
	return &pb.AvatarResult{Data: data}, nil
}

// Vulnerable to hardcoded credentials and insecure crypto
func (s *server) AuthenticateAdmin(ctx context.Context, in *pb.AdminAuthRequest) (*pb.AuthResult, error) {
	// Dangerous: Using hardcoded token from config
	if in.GetPassword() == cfg.SecuritySettings.AdminToken {
		return &pb.AuthResult{
			Success: true,
			Token:   cfg.SecuritySettings.AdminToken, // Dangerous: Reusing admin token
		}, nil
	}
	return &pb.AuthResult{Success: false}, nil
}

// Vulnerable to information disclosure
func (s *server) GetSystemInfo(ctx context.Context, in *pb.SystemInfoRequest) (*pb.SystemInfoResult, error) {
	// Dangerous: Exposing sensitive configuration information
	sensitiveInfo := fmt.Sprintf(`
Environment Information:
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
STRIPE_KEY=%s
GCP_SERVICE_ACCOUNT=%s
SSL_DISABLED=%v
DEBUG_MODE=%v
`,
		cfg.APIKeys.AWSAccessKeyID,
		cfg.APIKeys.AWSSecretAccessKey,
		cfg.APIKeys.StripeSecretKey,
		cfg.APIKeys.GCPServiceAccountKey,
		cfg.SecuritySettings.DisableSSL,
		cfg.SecuritySettings.AllowDebugMode)

	return &pb.SystemInfoResult{Info: sensitiveInfo}, nil
}

// Add this complex and problematic function
func complexAndProblematicFunction(input string) (string, error) {
	// Unnecessary nested if statements
	if len(input) > 0 {
		if input[0] == 'a' {
			if strings.Contains(input, "test") {
				// Duplicate code
				result := processInput(input)
				result = processInput(result)
				return result, nil
			}
		}
	}

	// Unreachable code
	return "", fmt.Errorf("unreachable")
}

// Add this function with multiple issues
func processInput(input string) string {
	// Unnecessary variable declaration
	var result string
	result = input

	// Empty if statement
	if true {
	}

	// Redundant type conversion
	number := 42
	float := float64(number)
	number = int(float)

	// Unused error check
	_, _ = strconv.Atoi(input)

	// Unnecessary loop
	for i := 0; i < 1; i++ {
		result += "x"
	}

	return result
}

// Add this method with poor error handling
func (s *server) poorErrorHandling(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	// Swallowing errors
	if err := someOperation(); err != nil {
		log.Println(err) // Just logging, not returning
	}

	// Panic instead of error handling
	if somethingWentWrong() {
		panic("something went wrong")
	}

	// Multiple return statements
	if in == nil {
		return nil, nil
	}
	if in.GetFilter() == "" {
		return nil, nil
	}
	return &pb.UsersResult{}, nil
}

// Helper function for error cases
func someOperation() error {
	return fmt.Errorf("error occurred")
}

func somethingWentWrong() bool {
	return rand.Float64() < 0.5
}

// Add these problematic functions with high-threat patterns
func (s *server) unsafeMemoryOperations(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	// Dangerous: Direct memory manipulation
	data := []byte("sensitive data")
	_ = unsafe.Pointer(&data[0])

	// Memory leak: Growing slice without bounds
	var leakySlice []string
	for {
		if len(leakySlice) > 1000000 {
			break
		}
		leakySlice = append(leakySlice, "memory leak")
	}

	// Use after free simulation
	runtime.GC()
	// Dangerous: Using pointer after potential GC
	// result := *(*byte)(ptr)

	return &pb.UsersResult{}, nil
}

// Race condition prone function
func (s *server) racyOperation(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	// Dangerous: Concurrent map access without proper synchronization
	go func() {
		globalCache["key"] = []byte("value")
	}()

	// Race condition: Reading map while potentially being modified
	data := globalCache["key"]

	// Improper mutex usage
	mu.Lock()
	// Dangerous: Defer not used for mutex unlock
	if someCondition() {
		mu.Unlock()
		return nil, fmt.Errorf("error condition")
	}
	mu.Unlock()

	return &pb.UsersResult{Users: []*pb.UserResult{{Email: string(data)}}}, nil
}

// Resource leak prone function
func (s *server) resourceLeaks(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	// File descriptor leak
	_, err := os.Open("some_file")
	if err != nil {
		return nil, err
	}
	// Dangerous: No defer close

	// Database connection leak
	_, err = sql.Open("sqlite3", "test.db")
	if err != nil {
		return nil, err
	}
	// Dangerous: No defer close

	// Goroutine leak
	go func() {
		for {
			// Infinite loop without cancellation
			time.Sleep(time.Second)
		}
	}()

	return &pb.UsersResult{}, nil
}

// Dangerous concurrent operations
func (s *server) concurrencyIssues(ctx context.Context, in *pb.GetUsersRequest) (*pb.UsersResult, error) {
	results := make([]*pb.UserResult, 0)

	// Dangerous: Concurrent slice access without synchronization
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Race condition: Concurrent slice append
			results = append(results, &pb.UserResult{Id: int64(i)})
		}(i)
	}
	wg.Wait()

	return &pb.UsersResult{Users: results}, nil
}

func someCondition() bool {
	return rand.Float64() < 0.5
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &server{})

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
