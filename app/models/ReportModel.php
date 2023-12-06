<?php

namespace App\Models;

use app\repositories\ReportRepository;
use Exception;
use app\infra\Database\Connection;
use app\middlewares\AuthMiddleware;
use PDO;

class ReportModel implements ReportRepository
{
    private PDO $conn;
    private AuthMiddleware $authMiddleware;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
        $this->authMiddleware = new AuthMiddleware($this->conn);
    }

    public function create($params): array | Exception
    {
        try {
            $auth_email = $params->auth_email;
            $auth_token = $params->auth_token;
            $title = $params->title;
            $description = $params->description;
            $user_id = $params->user_id;

            if (!isset($auth_email) || !isset($token) || !isset($title) || !isset($description) || !isset($user_id)) {
                $data = [
                    'code' => 400,
                    'response' => [
                        'message' => 'All fields are required',
                    ],
                ];

                return $data;
            }

            $auth = $this->authMiddleware->handleCheckPermissionAdmin($auth_email);

            if (!$auth) {
                $data = [
                    'code' => 401,
                    'response' => [
                        'message' => 'Unauthorized',
                    ],
                ];

                return $data;
            }

            $validateToken = $this->authMiddleware->handleValidateToken($auth_email, $auth_token);

            if (!$validateToken) {
                $httpCode = 401;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Unauthorized',
                    ],
                ];

                return $data;
            }

            return [];
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}