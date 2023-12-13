<?php

namespace app\controllers;

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
    public function create()
    {
        try {
            $data = $this->reportModel->create();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function getAll()
    {
        try {
            $data = $this->reportModel->getAll();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function delete()
    {
        try {
            $data = $this->reportModel->delete();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function update()
    {
        try {
            $data = $this->reportModel->update();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}