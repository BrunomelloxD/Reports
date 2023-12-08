<?php

namespace App\Repositories;

use Exception;

interface ReportRepository
{
    public function create($params): array | Exception;
    public function getAll($params): array | Exception;
    public function delete($params): array | Exception;
}