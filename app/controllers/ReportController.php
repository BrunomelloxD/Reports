<?php

namespace app\Controllers;

use app\views\Response;
use app\models\ReportModel;
use app\infra\database\Connection;

class ReportController
{
    private $connection;
    private $reportModel;

    public function __construct()
    {
        $dbHost = $_ENV['DB_HOST'];
        $dbName = $_ENV['DB_NAME'];
        $dbUser = $_ENV['DB_USER'];
        $dbPassword = $_ENV['DB_PASSWORD'];

        $this->connection = new Connection($dbHost, $dbName, $dbUser, $dbPassword);
        $this->reportModel = new ReportModel($this->connection);
    }

    public function create(object $params)
    {
        try {
            $data = $this->reportModel->create($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function getAll(object $params)
    {
        try {
            $data = $this->reportModel->getAll($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function delete(object $params)
    {
        try {
            $data = $this->reportModel->delete($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}