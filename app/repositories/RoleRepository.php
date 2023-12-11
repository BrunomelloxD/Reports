<?php

namespace App\Repositories;

use Exception;

interface RoleRepository
{
    public function create(): array | Exception;
    public function getAll(): array | Exception;
    public function get(): array | Exception;
    public function delete(): array | Exception;
    public function update(): array | Exception;
}