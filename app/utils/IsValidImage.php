<?php

namespace App\Utils;

class IsValidImage
{
    function handle($image): bool
    {
        $imagePath = $image['tmp_name'];
        $imageSize = getimagesize($imagePath);
        $imageType = $imageSize[2];

        if ($imageType !== IMAGETYPE_JPEG && $imageType !== IMAGETYPE_PNG) {
            return false;
        }

        return true;
    }
}