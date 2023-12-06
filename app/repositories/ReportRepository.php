<?php

namespace App\Repositories;

use Exception;

interface ReportRepository
{
    public function create($params): array | Exception;
}