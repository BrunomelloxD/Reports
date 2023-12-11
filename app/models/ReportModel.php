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

    public function create(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $title = $_GET['title'];
            $description = $_GET['description'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($title) || !isset($description)) {
                $httpCode = 400;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'All fields are required',
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
                        'message' => 'Unauthorized',
                    ],
                ];

                return $data;
            }

            // Getting user id
            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $auth_email);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $user_id = $user['id'];

            // Inserting report
            $sql = "INSERT INTO reports (title, description, user_id) VALUES (:title, :description, :user_id)";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->execute();

            $httpCode = 201;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Report created successfully',
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
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $user_id = $_GET['user_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($user_id)) {
                $httpCode = 400;
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
                        'message' => 'User is not authorized',
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
                        'message' => 'Unauthorized',
                    ],
                ];

                return $data;
            }

            // Getting reports
            $sql = "SELECT * FROM reports WHERE user_id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':user_id', $user_id);
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

    public function delete(): array | Exception
    {
        try {
            $auth_email = $_GET['auth_email'];
            $auth_token = $_GET['auth_token'];
            $report_id = $_GET['report_id'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($report_id)) {
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

            // Getting user id
            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $auth_email);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $user_id = $user['id'];

            // Deleting report
            $sql = "DELETE FROM reports WHERE id = :report_id AND user_id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':report_id', $report_id);
            $stmt->bindParam(':user_id', $user_id);
            $response = $stmt->execute();

            if (!$response) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error deleting report',
                    ],
                ];
                return $data;
            }

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Report deleted successfully',
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
            $report_id = $_GET['report_id'];
            $title = $_GET['title'];
            $description = $_GET['description'];

            if (!isset($auth_email) || !isset($auth_token) || !isset($report_id) || !isset($title) || !isset($description)) {
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

            // Getting user id
            $sql = "SELECT id FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':email', $auth_email);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $user_id = $user['id'];

            // Updating report
            $sql = "UPDATE reports SET title = :title, description = :description WHERE id = :report_id AND user_id = :user_id";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':report_id', $report_id);
            $stmt->bindParam(':user_id', $user_id);
            $response = $stmt->execute();

            if (!$response) {
                $httpCode = 500;
                $data = [
                    'code' => $httpCode,
                    'response' => [
                        'code' => $httpCode,
                        'message' => 'Error updating report',
                    ],
                ];
                return $data;
            }

            $httpCode = 200;
            $data = [
                'code' => $httpCode,
                'response' => [
                    'code' => $httpCode,
                    'message' => 'Report updated successfully',
                ],
            ];

            return $data;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}