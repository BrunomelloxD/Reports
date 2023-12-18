<?php

namespace App\Repositories;

use Exception;

interface RoleRepository
{
    public function getAll(): array | Exception;
}