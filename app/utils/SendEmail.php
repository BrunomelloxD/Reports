<?php

namespace App\Utils;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class SendEmail
{
    public function handle($email, $password)
    {
        $mail = new PHPMailer(true);
        define("LOGIN", $_ENV["EMAIL_LOGIN"]);
        define("PASSWORD", $_ENV["EMAIL_PASSWORD"]);

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
            $mail->Subject = "Cadastro realizado com sucesso!";
            $mail->Body = "Senha gerada:" . "<br>" . $password;
            $mail->AltBody = "Senha gerada:" . "<br>" . $password;
            $response = $mail->send();

            return $response;
        } catch (\Throwable $th) {
            echo $th->getMessage();
            throw new \RuntimeException('Error:', 0, $th);
        }
    }
}