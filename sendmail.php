<?php
// Bezpečné odeslání kontaktního formuláře
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method Not Allowed');
}

// Nastavení správného kódování
mb_internal_encoding('UTF-8');

// Základní validace a sanitizace
function clean($str) {
    return htmlspecialchars(trim($str), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Rate limiting - jednoduchá ochrana před spam útoky
session_start();
$now = time();
if (isset($_SESSION['last_mail_time']) && ($now - $_SESSION['last_mail_time']) < 60) {
    http_response_code(429);
    exit('Příliš mnoho požadavků. Zkuste to později.');
}

$name = isset($_POST['Jméno']) ? clean($_POST['Jméno']) : '';
$email = isset($_POST['E-mail']) ? clean($_POST['E-mail']) : '';
$message = isset($_POST['Zpráva']) ? clean($_POST['Zpráva']) : '';

// Kontrola povinných polí
if (!$name || !$email || !$message) {
    http_response_code(400);
    exit('Chybí povinné údaje.');
}

// Validace emailu
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit('Neplatný e-mail.');
}

// Ochrana proti spamu (honeypot)
if (!empty($_POST['phone'])) {
    http_response_code(400);
    exit('Spam detekován.');
}

// Kontrola délky zprávy
if (strlen($message) > 2000) {
    http_response_code(400);
    exit('Zpráva je příliš dlouhá.');
}

// Sestavení zprávy
$to = 'doprava@roudny.cz';
$subject = '=?UTF-8?B?' . base64_encode('Nová zpráva z webu Jiří Roudný - DOPRAVA, SPEDICE') . '?=';

// HTML verze zprávy
$htmlBody = "
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>Nová zpráva z kontaktního formuláře</title>
</head>
<body style='font-family: Arial, sans-serif;'>
    <h2>Nová zpráva z kontaktního formuláře</h2>
    <table border='1' cellpadding='10' cellspacing='0' style='border-collapse: collapse;'>
        <tr>
            <td><strong>Jméno:</strong></td>
            <td>" . htmlspecialchars($name) . "</td>
        </tr>
        <tr>
            <td><strong>E-mail:</strong></td>
            <td>" . htmlspecialchars($email) . "</td>
        </tr>
        <tr>
            <td><strong>Zpráva:</strong></td>
            <td>" . nl2br(htmlspecialchars($message)) . "</td>
        </tr>
        <tr>
            <td><strong>Datum a čas:</strong></td>
            <td>" . date('d.m.Y H:i:s') . "</td>
        </tr>
        <tr>
            <td><strong>IP adresa:</strong></td>
            <td>" . $_SERVER['REMOTE_ADDR'] . "</td>
        </tr>
    </table>
</body>
</html>
";

// Text verze zprávy
$textBody = "Nová zpráva z kontaktního formuláře\n\n";
$textBody .= "Jméno: $name\n";
$textBody .= "E-mail: $email\n";
$textBody .= "Zpráva:\n$message\n\n";
$textBody .= "Datum a čas: " . date('d.m.Y H:i:s') . "\n";
// $textBody .= "IP adresa: " . $_SERVER['REMOTE_ADDR'] . "\n";

// Boundary pro multipart zprávu
$boundary = md5(time());

// Kompletní hlavičky
$headers = array();
$headers[] = "From: $email";
$headers[] = "Reply-To: $email";
$headers[] = "Return-Path: noreply@roudny.cz";
$headers[] = "X-Mailer: PHP/" . phpversion();
$headers[] = "X-Priority: 3";
$headers[] = "MIME-Version: 1.0";
$headers[] = "Content-Type: multipart/alternative; boundary=\"$boundary\"";

// Sestavení multipart zprávy
$body = "--$boundary\r\n";
$body .= "Content-Type: text/plain; charset=UTF-8\r\n";
$body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
$body .= $textBody . "\r\n";
$body .= "--$boundary\r\n";
$body .= "Content-Type: text/html; charset=UTF-8\r\n";
$body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
$body .= $htmlBody . "\r\n";
$body .= "--$boundary--\r\n";

// Odeslání e-mailu
$success = @mail($to, $subject, $body, implode("\r\n", $headers));

if ($success) {
    $_SESSION['last_mail_time'] = $now;
    echo 'OK';
} else {
    // Logování chyby
    error_log("Chyba při odesílání e-mailu z formuláře: " . error_get_last()['message'], 0);
    http_response_code(500);
    echo 'Chyba při odesílání e-mailu.';
}
