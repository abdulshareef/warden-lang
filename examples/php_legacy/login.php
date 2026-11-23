<?php
session_start();
include 'inc/db.php';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $u = mysqli_real_escape_string($conn, $_POST['user']);
    $p = md5($_POST['pass']);
    $res = mysqli_query($conn, "SELECT * FROM users WHERE name='" . $u . "' AND pw='" . $p . "'");
    if (mysqli_num_rows($res) > 0) {
        $_SESSION['user'] = $u;
        header("Location: index.php");
        exit;
    }
    $error = "Bad login";
}
?>
<form method="post"><input name="user"><input name="pass" type="password"></form>
