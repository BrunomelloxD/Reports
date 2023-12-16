<?php

namespace App\Repositories;

use Exception;

interface ReportRepository
{
    public function create(): array | Exception;
    public function getAll(): array | Exception;
    public function delete(): array | Exception;
    public function update(): array | Exception;
}
