<?php
session_start();
require_once 'inc/db.php';
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = '$id'");
?>
<html><body>
<h1>Welcome <?php echo $_GET['name']; ?></h1>
<?php while ($row = mysqli_fetch_assoc($result)) { ?>
  <p><?= $row['title'] ?> - <?php echo h($row['price']); ?></p>
<?php } ?>
<?php if (isset($_SESSION['user'])): ?>
  <p>Logged in as <?= $_SESSION['user'] ?></p>
<?php endif; ?>
</body></html>
