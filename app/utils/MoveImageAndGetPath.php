<?php

namespace App\Utils;

class MoveImageAndGetPath
{
    public function handle($image)
    {
        $imageName = uniqid('image_') . '.' . pathinfo($image['name'], PATHINFO_EXTENSION);

        $uploadDir = $_ENV['UPLOAD_DIR'];

        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        $imagePath = $uploadDir . $imageName;
        $imageDB = substr($uploadDir, 2) . $imageName;

        move_uploaded_file($image['tmp_name'], $imagePath);

        return $imageDB;
    }
}