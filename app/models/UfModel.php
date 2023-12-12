<?php

namespace App\Models;

use app\repositories\UfRepository;
use app\infra\Database\Connection;
use app\middlewares\AuthMiddleware;
use Exception;
use PDO;

class UfModel implements UfRepository
{
    private PDO $conn;
    private $authMiddleware;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
        $this->authMiddleware = new AuthMiddleware($this->conn);
    }
    public function getAll(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];

            if (!isset($auth_email) || !isset($auth_token)) {
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

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token not valid',
                    ],
                ];
                return $data;
            }

            $sql = 'SELECT * FROM ufs';
            $stmt = $this->conn->prepare($sql);
            $stmt->execute();
            $response = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => $response,
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
            $uf_id = $_GET['uf_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($uf_id)) {
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

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token not valid',
                    ],
                ];
                return $data;
            }

            $sql = 'SELECT * FROM ufs WHERE id = :uf_id';
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':uf_id', $uf_id);
            $stmt->execute();
            $response = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => $response,
            ];
            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
    public function create(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $uf_name = $_GET['uf_name'];

            if (!isset($auth_email) || !isset($auth_token)) {
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

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token not valid',
                    ],
                ];
                return $data;
            }

            $sql = 'INSERT INTO ufs (uf_name) VALUES (:uf_name)';
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':uf_name', $uf_name);
            $response = $stmt->execute();

            if(!$response) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error creating UF',
                    ],
                ];
                return $data;
            }

            $httpCode = 201;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'UF created successfully',
                ],
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
            $uf_id = $_GET['uf_id'];

            if (!isset($auth_email) || !isset($auth_token)) {
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

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token not valid',
                    ],
                ];
                return $data;
            }

            $sql = 'DELETE FROM ufs WHERE id = :uf_id';
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':uf_id', $uf_id);
            $response = $stmt->execute();

            if(!$response) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error deleting UF',
                    ],
                ];
                return $data;
            }

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'UF deleted successfully',
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
            $uf_id = $_GET['uf_id'];
            $uf_name = $_GET['uf_name'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($uf_id) || !isset($uf_name)) {
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

            $validateToken = $this->authMiddleware->handleValidateLoginToken($auth_email, $auth_token);
            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Token not valid',
                    ],
                ];
                return $data;
            }

            $sql = 'UPDATE ufs SET uf_name = :uf_name WHERE id = :uf_id';
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':uf_id', $uf_id);
            $stmt->bindValue(':uf_name', $uf_name);
            $response = $stmt->execute();

            if(!$response) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error updating UF',
                    ],
                ];
                return $data;
            }

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'UF updated successfully',
                ],
            ];
            return $data;

        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}