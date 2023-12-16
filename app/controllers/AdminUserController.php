<?php

namespace app\controllers;

use app\views\Response;
use app\models\UserModel;
use app\infra\database\Connection;

class AdminUserController
{
    private $connection;
    private $userModel;

    public function __construct()
    {
        $dbHost = $_ENV['DB_HOST'];
        $dbName = $_ENV['DB_NAME'];
        $dbUser = $_ENV['DB_USER'];
        $dbPassword = $_ENV['DB_PASSWORD'];

        $this->connection = new Connection($dbHost, $dbName, $dbUser, $dbPassword);
        $this->userModel = new UserModel($this->connection);
    }

    public function createUser()
    {
        try {
            $data = $this->userModel->create();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function deleteUser()
    {
        try {
            $data = $this->userModel->delete();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}