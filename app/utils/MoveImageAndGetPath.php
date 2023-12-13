<?php

namespace App\Utils;

class MoveImageAndGetPath
{
    public function handle($image)
    {
        $imageName = uniqid('image_') . '.' . pathinfo($image['name'], PATHINFO_EXTENSION);

        define('UPLOAD_DIR', $_ENV['UPLOAD_DIR']);

        if (!is_dir(UPLOAD_DIR)) {
            mkdir(UPLOAD_DIR, 0777, true);
        }

        $imagePath = UPLOAD_DIR . $imageName;
        $imageDB = substr(UPLOAD_DIR, 2) . $imageName;

        move_uploaded_file($image['tmp_name'], $imagePath);

        return $imageDB;
    }
}