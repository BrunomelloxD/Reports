<?php

namespace App\Repositories;

use Exception;

interface UfRepository
{
    public function getAll(): array | Exception;
    public function get(): array | Exception;
}