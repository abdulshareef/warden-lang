<?php
$conn = mysqli_connect("localhost", "root", "secret", "shop") or die(mysqli_error($conn));
function h($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
