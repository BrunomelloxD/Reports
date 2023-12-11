<?php

namespace App\Models;

use app\repositories\RoleRepository;
use app\infra\Database\Connection;
use app\middlewares\AuthMiddleware;
use Exception;
use PDO;

class RoleModel implements RoleRepository
{
    private PDO $conn;
    private $authMiddleware;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
        $this->authMiddleware = new AuthMiddleware($this->conn);
    }
    public function create(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $role_name = $_GET['role_name'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($role_name)) {
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

            $role_name = ucfirst(strtolower($role_name));

            $sql = "INSERT INTO roles (role_name) VALUES (:role_name)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':role_name', $role_name);
            $stmt->execute();

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Role created successfully!',
                ],
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
            $sql = "SELECT * FROM roles";
            $stmt = $this->conn->prepare($sql);
            $stmt->execute();
            $response = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $data = [
                'code' => 200,
                'response' => $response
            ];
            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
    public function get(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $role_id = $_GET['role_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($role_id)) {
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

            $sql = "SELECT * FROM roles WHERE id = :role_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':role_id', $role_id);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$response) {
                $httpCode = 404;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Role not found',
                    ],
                ];
                return $data;
            }

            $data = [
                'code' => 200,
                'response' => $response
            ];
            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
    public function delete(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $role_id = $_GET['role_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($role_id)) {
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

            $sql = "DELETE FROM roles WHERE id = :role_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':role_id', $role_id);
            $stmt->execute();

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Role deleted successfully!',
                ],
            ];
            return $data;
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
            $role_id = $_GET['role_id'];
            $role_name = $_GET['role_name'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($role_id) || !isset($role_name)) {
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

            $sql = "UPDATE roles SET role_name = :role_name WHERE id = :role_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':role_id', $role_id);
            $stmt->bindParam(':role_name', $role_name);
            $stmt->execute();

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Role updated successfully!',
                ],
            ];
            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}