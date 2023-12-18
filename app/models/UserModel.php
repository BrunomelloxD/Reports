<?php

namespace app\models;

use app\repositories\UserRepository;
use app\infra\Database\Connection;
use app\middlewares\AuthMiddleware;
use app\utils\GenerateToken;
use app\utils\RandomPassword;
use app\utils\SendEmail;
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

    // Supervisor only


    // Admin only
    public function create(): array | Exception
    {
        try {
            $auth_email = $_POST['auth_email'];
            $auth_token = $_POST['auth_token'];
            $username = $_POST['name'];
            $email = $_POST['email'];
            $role_id = $_POST['role_id'];
            $uf = $_POST['uf_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($username) || !isset($email) || !isset($role_id) || !isset($uf)) {
                $httpCode = 422;
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
            if (!$auth) {
                $httpCode = 403;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Permission denied',
                    ],
                ];
                return $data;
            }

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Invalid token',
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

            $randomPassword = new RandomPassword();
            $password = $randomPassword->handle();

            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            // Creating the user
            $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':username', $username);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':password', $hashedPassword);
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

            $title = "Report System - Cadastro realizado com sucesso!";
            $body = "Boas Vindas, " . $username . ". Seu cadastro foi realizado com sucesso. Acesse o <a href='https://google.com.br'>link</a> abaixo para fazer login com a senha:<br><br>" . $password . "<br><br>Atenciosamente,<br>Equipe Report";

            $sendEmail =  new SendEmail;
            $sendEmail->handle($email, $title, $body);

            $httpCode = 201;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'User created successfully!',
                ],
            ];

            return $data;
        } catch (\Exception $e) {
            echo $e->getMessage();
            throw new \RuntimeException('Error:', 0, $e);
        }
    }
    public function delete(): array | Exception
    {
        try {
            $email = $_GET['auth_email'];
            $token = $_GET['auth_token'];
            $userId = $_GET['user_id'];

            if (!isset($email) || !isset($userId) || !isset($token)) {
                $httpCode = 422;
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

    // User Profile
    public function getUser(): array | Exception
    {
        try {
            $user_id = $_GET['user_id'];

            if (!isset($user_id)) {
                $httpCode = 422;
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

            $sqlReports = "SELECT * FROM reports WHERE user_id = :id";
            $stmtReports = $this->conn->prepare($sqlReports);
            $stmtReports->bindValue(':id', $user_id);
            $stmtReports->execute();
            $reports = $stmtReports->fetchAll(PDO::FETCH_ASSOC);

            $response = [
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
    public function getAll(): array | Exception
    {
        try {
            $email = $_GET['auth_email'];
            $token = $_GET['auth_token'];

            if (!isset($email) || !isset($token)) {
                $httpCode = 422;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $auth = $this->authMiddleware->handleCheckPermissionSupervisor($email);
            if (!$auth) {
                $httpCode = 403;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Unauthorized'
                    ],
                ];
                return $data;
            }

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
            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch();
            $user_id = $response['id'];

            $sql = "SELECT uf_id FROM user_uf_relations WHERE user_id = :id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':id', $user_id);
            $stmt->execute();
            $response = $stmt->fetch();
            $uf_id = $response['uf_id'];

            $sql = "SELECT users.id, users.username, users.email, users.created_at, roles.role_name, ufs.uf_name, COUNT(reports.id) AS reports_count 
            FROM users 
            JOIN user_roles ON users.id = user_roles.user_id 
            JOIN roles ON user_roles.role_id = roles.id 
            JOIN user_uf_relations ON users.id = user_uf_relations.user_id 
            JOIN ufs ON user_uf_relations.uf_id = ufs.id 
            LEFT JOIN reports ON users.id = reports.user_id 
            WHERE user_uf_relations.uf_id = :id AND users.email != :email AND user_roles.role_id != 1 AND user_roles.role_id != 2
            GROUP BY users.id, users.username, users.email, users.created_at, roles.role_name, ufs.uf_name;";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':id', $uf_id);
            $stmt->bindParam(':email', $email);
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
    public function login(): array | Exception
    {
        try {
            $email = $_POST['email'];
            $password = $_POST['password'];

            if (!isset($email) || !isset($password)) {
                $httpCode = 422;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT * FROM users  WHERE email = :email";
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
                    'access_token' => $token
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
    public function update(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $user_id = $_GET['user_id'];
            $username = $_GET['name'];
            $email = $_GET['email'];
            $role_id = $_GET['role_id'];
            $uf = $_GET['uf'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($user_id) || !isset($username) || !isset($email) || !isset($role_id) || !isset($uf)) {
                $httpCode = 422;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            // Check if user is admin
            $auth = $this->authMiddleware->handleCheckPermissionAdmin($auth_email);
            if (!$auth) {
                $httpCode = 403;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'User not authorized',
                    ],
                ];
                return $data;
            }

            // Check if token is valid
            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Invalid token',
                    ],
                ];
                return $data;
            }

            // Select user id
            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $user = $stmt->fetch();

            // User not found in database
            $id = $user['id'];
            if ($user_id != $id) {
                $httpCode = 404;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'User id and email not match',
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
    public function generateTokenResetPassword(): array | Exception
    {
        try {
            $email = $_POST['email'];

            if (!isset($email)) {
                $httpCode = 422;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Email is required',
                    ],
                ];
                return $data;
            }

            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch();

            if (!$response) {
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

            $generateToken = new GenerateToken();
            $timeExpireToken = 1;
            [$token, $time] = $generateToken->handle($timeExpireToken);

            $sql = "UPDATE users SET reset_password_token = :token, reset_token_expires_at = :time WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':token', $token);
            $stmt->bindValue(':time', $time);
            $stmt->bindValue(':email', $email);
            $stmt->execute();

            $title = 'Report - Redefinir senha';
            $body = 'Clique no link abaixo e utilize o token para redefinir sua senha: ' . $token;

            $sendEmail = new SendEmail();
            $sendEmail->handle($email, $title, $body);

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Email sent successfully',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
    public function resetPassword(): array | Exception
    {
        try {
            $email = $_POST['email'];
            $token = $_POST['token'];
            $password = $_POST['password'];

            if (!isset($email) || !isset($token) || !isset($password)) {
                $httpCode = 422;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
                    ],
                ];
                return $data;
            }

            $validateToken = $this->authMiddleware->handleValidateResetPasswordToken($email, $token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Invalid token',
                    ],
                ];
                return $data;
            }

            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $sql = "UPDATE users SET password = :password, reset_password_token = NULL, reset_token_expires_at = NULL WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->bindParam(':email', $email);
            $stmt->execute();

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Password updated successfully',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}