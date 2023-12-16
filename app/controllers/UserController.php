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

    public function create()
    {
        try {
            $data = $this->userModel->create();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }

    public function getUser()
    {
        try {
            $data = $this->userModel->getUser();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function getAll()
    {
        try {
            $data = $this->userModel->getAll();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function login()
    {
        try {
            $data = $this->userModel->login();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function update()
    {
        try {
            $data = $this->userModel->update();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function generateTokenResetPassword()
    {
        try {
            $data = $this->userModel->generateTokenResetPassword();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
    public function resetPassword()
    {
        try {
            $data = $this->userModel->resetPassword();

            return Response::json($data);
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException($th);
        }
    }
}