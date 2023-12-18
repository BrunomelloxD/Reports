<?php

namespace app\controllers;

use app\views\Response;
use app\models\ReportModel;
use app\infra\database\Connection;

class SupervisorController
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

    public function getAllReportsByUser()
    {
        try {
            $data = $this->reportModel->getAllReportsByUser();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}