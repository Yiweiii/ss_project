
<?php
$raw = $_POST['matapelajaran'];
$clean = $_POST['idmatapelajaran'];
$raw = mysql_real_escape_string($raw);
$clean = mysql_real_escape_string($clean);
$query = "UPDATE matapelajaran SET matapelajaran='$raw' WHERE id_matapelajaran='$clean'";
mysql_query($query,$koneksi);
?>

