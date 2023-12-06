<?php

namespace app\views;

class Response
{
    public static function json($data): void
    {
        ['response' => $data, 'code' => $code] = $data;

        header("Content-type: application/json; charset=UTF-8");
        http_response_code($code);
        echo json_encode($data);
    }
}