<?php

namespace App\Repositories;

use Exception;

interface UserRepository
{
    public function create(): array | Exception;
    public function getUser(): array | Exception;
    public function getAll(): array | Exception;
    public function login(): array | Exception;
    public function delete(): array | Exception;
    public function update(): array | Exception;
}