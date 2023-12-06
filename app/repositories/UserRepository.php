<?php

namespace App\Repositories;

use Exception;

interface UserRepository
{
    public function create($params): array | Exception;
    public function getUser($params): array | Exception;
    public function getAll($params): array | Exception;
    public function login($params): array | Exception;
    public function delete($params): array | Exception;
    public function update($params): array | Exception;
}