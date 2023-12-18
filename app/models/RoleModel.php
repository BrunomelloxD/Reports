<?php

namespace App\Models;

use app\repositories\RoleRepository;
use app\infra\Database\Connection;
use Exception;
use PDO;

class RoleModel implements RoleRepository
{
    private PDO $conn;
    public function __construct(Connection $database)
    {
        $this->conn = $database->getConnection();
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
}