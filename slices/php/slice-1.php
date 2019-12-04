<?php
$raw = $_POST['matapelajaran'];
$clean = $_POST['idmatapelajaran'];
$clean = mysql_real_escape_string($clean);
$query = "UPDATE matapelajaran SET matapelajaran='$raw' WHERE id_matapelajaran='$clean'";
mysql_query($query,$koneksi);
?>

