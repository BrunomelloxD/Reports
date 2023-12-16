<?php

namespace App\Utils;

use PHPMailer\PHPMailer\PHPMailer;

class SendEmail
{
    public function handle($email, $title, $body)
    {
        define("LOGIN", $_ENV["EMAIL_LOGIN"]);
        define("PASSWORD", $_ENV["EMAIL_PASSWORD"]);

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = "smtp.office365.com";
            $mail->SMTPAuth = true;
            $mail->Username = LOGIN;
            $mail->Password = PASSWORD;
            $mail->Port = 587;

            $mail->setFrom(LOGIN, "Report Alares");
            $mail->addAddress($email);

            $mail->isHTML(true);
            $mail->Subject = $title;
            $mail->Body = $body;
            $response = $mail->send();

            return $response;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}
