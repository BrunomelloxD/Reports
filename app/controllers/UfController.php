<?php

namespace App\Controllers;

use app\models\UfModel;
use app\infra\database\Connection;
use app\views\Response;

class UfController
{
    private $connection;
    private $ufModel;

    public function __construct()
    {
        $dbHost = $_ENV['DB_HOST'];
        $dbName = $_ENV['DB_NAME'];
        $dbUser = $_ENV['DB_USER'];
        $dbPassword = $_ENV['DB_PASSWORD'];

        $this->connection = new Connection($dbHost, $dbName, $dbUser, $dbPassword);
        $this->ufModel = new UfModel($this->connection);
    }

    public function getAll()
    {
        try {
            $data = $this->ufModel->getAll();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function get()
    {
        try {
            $data = $this->ufModel->get();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}