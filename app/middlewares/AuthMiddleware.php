<?php

namespace app\middlewares;

use Exception;
use PDO;

class AuthMiddleware
{
    private $pdo;
    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function handleCheckPermissionAdmin($email): bool | Exception
    {
        try {
            $sql = "SELECT roles.id
            FROM users
            JOIN user_roles ON users.id = user_roles.user_id
            JOIN roles ON user_roles.role_id = roles.id
            WHERE users.email = :email";

            $stmt = $this->pdo->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($response['id'] === 1) {
                return true;
            }

            return false;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }

    public function handleValidateLoginToken($email, $userToken): bool | Exception
    {
        try {
            $sql = "SELECT login_token_expires_at, login_token FROM users WHERE email = :email AND login_token = :token";
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':token', $userToken);
            $stmt->execute();
            $response = $stmt->fetch(PDO::FETCH_ASSOC);

            $loginTokenExpiresAt = $response['login_token_expires_at'];
            $token = $response['login_token'];

            if (!$token) {
                return false;
            }

            $currentDate = date('Y-m-d H:i:s');

            if ($loginTokenExpiresAt >= $currentDate) {
                return true;
            }

            $sql = "UPDATE users SET login_token_expires_at = NULL, login_token = NULL WHERE email = :email";
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindValue(':email', $email);
            $stmt->execute();

            echo 'ok';

            return false;
        } catch (\Throwable $th) {
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}