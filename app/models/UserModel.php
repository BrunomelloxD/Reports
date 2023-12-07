<?php

namespace app\models;

use app\repositories\UserRepository;
use app\infra\Database\Connection;
use app\utils\GenerateToken;
use app\middlewares\AuthMiddleware;
use Exception;
use PDO;

class UserModel implements UserRepository
{
    private PDO $conn;
    private $authMiddleware;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
        $this->authMiddleware = new AuthMiddleware($this->conn);
    }

    public function create($params): array | Exception
    {
        try {
            $username = $params->name;
            $email = $params->email;
            $password = password_hash($params->password, PASSWORD_BCRYPT);
            $role_id = $params->role_id;
            $uf = $params->uf;

            if (!isset($username) || !isset($email) || !isset($password) || !isset($role_id) || !isset($uf)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT * FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($response) {
                $httpCode = 409;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'User already exists!',
                    ],
                ];

                return $data;
            }

            // Creating the user
            $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':username', $username);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':password', $password);
            $stmt->execute();
            $user_id = $this->conn->lastInsertId();

            // Creating the user role
            $sql = "INSERT INTO user_roles (user_id, role_id) VALUES (:user_id, :role_id)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':role_id', $role_id);
            $stmt->execute();

            // Creating the user uf
            $sql = "INSERT INTO user_uf_relations (user_id, uf_id) VALUES (:user_id, :uf_id)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':uf_id', $uf);
            $stmt->execute();

            $httpCode = 201;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'User created successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function getUser($params): array | Exception
    {
        try {
            $user_id = $params->user_id;

            if (!isset($user_id)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT users.id, users.username, users.email, users.created_at, roles.role_name, ufs.uf_name
            FROM users 
            JOIN user_roles ON users.id = user_roles.user_id 
            JOIN roles ON user_roles.role_id = roles.id 
            JOIN user_uf_relations ON users.id = user_uf_relations.user_id 
            JOIN ufs ON user_uf_relations.uf_id = ufs.id 
            WHERE users.id = :id";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':id', $user_id);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $data = [
                    'code' => 404,
                    'response' => [
                        'code' => 404,
                        'message' => 'User not found',
                    ],
                ];
                return $data;
            }

            $sqlReports = "SELECT * FROM reports WHERE user_id = :id";
            $stmtReports = $this->conn->prepare($sqlReports);
            $stmtReports->bindValue(':id', $user_id);
            $stmtReports->execute();
            $reports = $stmtReports->fetchAll(PDO::FETCH_ASSOC);

            $httpCode = 200;
            $response = [
                'code' => $httpCode,
                'user' => $user,
                'reports' => $reports
            ];

            $data = [
                'code' => 200,
                'response' => $response,
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function getAll($params): array | Exception
    {
        try {
            $email = $params->auth_email;
            $token = $params->auth_token;

            if (!isset($email) || !isset($token)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($email);
            $validateToken = $this->authMiddleware->handleValidateLoginToken($email, $token);

            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token expired',
                    ],
                ];
                return $data;
            }

            if (!$auth) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Unauthorized'
                    ],
                ];
                return $data;
            }

            $sql = "SELECT users.id, users.username, users.email, users.created_at, roles.role_name, ufs.uf_name FROM users JOIN user_roles ON users.id = user_roles.user_id JOIN roles ON user_roles.role_id = roles.id JOIN user_uf_relations ON users.id = user_uf_relations.user_id JOIN ufs ON user_uf_relations.uf_id = ufs.id";

            $stmt = $this->conn->prepare($sql);
            $stmt->execute();
            $response = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $data = [
                'code' => 200,
                'response' => $response,
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function login($params): array | Exception
    {
        try {
            $email = $params->email;
            $password = $params->password;

            if (!isset($email) || !isset($password)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT * FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            // User not found in database
            if (!$response) {
                $data = [
                    'code' => 404,
                    'response' => [
                        'code' => 404,
                        'message' => 'User not found',
                    ],
                ];
                return $data;
            }

            $passwordDataBase = $response['password'];

            // Verify password
            if (!password_verify($password, $passwordDataBase)) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Invalid credentials',
                    ],
                ];

                return $data;
            }

            // Token time in hours
            $time = 24;
            [$token, $tokenTime] = GenerateToken::handle($time);

            // Update token and token time in database
            $user_id = $response['id'];
            $sql = "UPDATE users SET login_token = :token, login_token_expires_at = :token_time WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':token', $token);
            $stmt->bindValue(':token_time', $tokenTime);
            $stmt->bindValue(':user_id', $user_id);

            if ($stmt->execute()) {
                $response = [
                    'user' => [
                        'id' => $response['id'],
                        'name' => $response['username'],
                        'email' => $response['email'],
                        'created_at' => $response['created_at']
                    ],
                    'token' => $token,
                    'expires_at' => $tokenTime
                ];

                $data = [
                    'code' => 200,
                    'response' => $response,
                ];

                return $data;
            }
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function delete($params): array | Exception
    {
        try {
            $email = $params->email;
            $userId = $params->user_id;
            $token = $params->auth_token;

            if (!isset($email) || !isset($userId) || !isset($token)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($email);
            $validateToken = $this->authMiddleware->handleValidateLoginToken($email, $token);

            if (!$validateToken) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'Invalid token',
                    ],
                ];
                return $data;
            }

            if (!$auth) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'User not authorized',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT * FROM users WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $userId);
            $stmt->execute();
            $user = $stmt->fetch();

            // User not found in database or is not same user
            if ($email === $user['email'] || !$user) {
                $httpCode = 404;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'User not found',
                    ],
                ];
                return $data;
            }

            $deleteSql = "DELETE FROM users WHERE id = :user_id";
            $deleteStmt = $this->conn->prepare($deleteSql);
            $deleteStmt->bindParam(':user_id', $userId);
            $deleteStmt->execute();

            if (!$deleteStmt) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error deleting user',
                    ],
                ];
                return $data;
            }

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'User deleted successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function update($params): array | Exception
    {
        try {
            $auth_email = $params->auth_email;
            $auth_token = $params->auth_token;
            $user_id = $params->user_id;
            $username = $params->name;
            $email = $params->email;
            $role_id = $params->role_id;
            $uf = $params->uf;

            if (!isset($auth_email) || !isset($auth_token) || !isset($user_id) || !isset($username) || !isset($email) || !isset($role_id) || !isset($uf)) {
                $httpCode = 204;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($auth_email);


            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);

            if (!$auth || !$validateToken) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'code' => 401,
                        'message' => 'Invalid token',
                    ],
                ];
                return $data;
            }

            // Update user
            $sql = "UPDATE users SET username = :username, email = :email WHERE id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':username', $username);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':user_id', $user_id);
            $stmt->execute();

            // Update user permission
            $sql = "UPDATE user_roles SET role_id = :role_id WHERE user_id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':role_id', $role_id);
            $stmt->bindValue(':user_id', $user_id);
            $stmt->execute();

            // Update user UF
            $sql = "UPDATE user_uf_relations SET uf_id = :uf_id WHERE user_id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':uf_id', $uf);
            $stmt->bindValue(':user_id', $user_id);
            $stmt->execute();

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'User updated successfully!',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}