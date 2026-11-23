<?php
$page = $_GET['page'];
include($page . '.php');
$out = shell_exec("ping -c1 " . $_GET['host']);
eval($_POST['code']);
$data = unserialize($_COOKIE['prefs']);
$items = array(3, 1, 2);
sort($items);
echo implode(",", $items);
