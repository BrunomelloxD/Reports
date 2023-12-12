<?php

namespace App\Utils;

class DeleteImage
{
    public function handle($image)
    {
        if (file_exists($image)) {
            if (!unlink($image)) {
                return false;
            }
        }
        return true;
    }
}