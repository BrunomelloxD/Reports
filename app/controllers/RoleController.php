<?php

namespace app\controllers;

use app\views\Response;
use app\models\RoleModel;
use app\infra\database\Connection;

class RoleController
{
    private $connection;
    private $roleModel;

    public function __construct()
    {
        $dbHost = $_ENV['DB_HOST'];
        $dbName = $_ENV['DB_NAME'];
        $dbUser = $_ENV['DB_USER'];
        $dbPassword = $_ENV['DB_PASSWORD'];

        $this->connection = new Connection($dbHost, $dbName, $dbUser, $dbPassword);
        $this->roleModel = new RoleModel($this->connection);
    }
    public function create()
    {
        try {
            $data = $this->roleModel->create();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function getAll()
    {
        try {
            $data = $this->roleModel->getAll();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function delete()
    {
        try {
            $data = $this->roleModel->delete();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function update()
    {
        try {
            $data = $this->roleModel->update();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function get()
    {
        try {
            $data = $this->roleModel->get();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}