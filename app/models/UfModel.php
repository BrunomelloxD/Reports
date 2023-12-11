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
}