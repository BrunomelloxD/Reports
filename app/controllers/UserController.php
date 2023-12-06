<?php

namespace app\controllers;

use app\views\Response;
use app\models\UserModel;
use app\infra\database\Connection;

class UserController
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

    public function create(object $params)
    {
        try {
            $data = $this->userModel->create($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function getUser(object $params)
    {
        try {
            $data = $this->userModel->getUser($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function getAll(object $params)
    {
        try {
            $data = $this->userModel->getAll($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function login(object $params)
    {
        try {
            $data = $this->userModel->login($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function delete(object $params)
    {
        try {
            $data = $this->userModel->delete($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function update(object $params)
    {
        try {
            $data = $this->userModel->update($params);

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}