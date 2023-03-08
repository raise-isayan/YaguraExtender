<?php
ini_set('display_errors', '0');

header("Content-type: text/html; charset=utf-8");
if ($_GET['mode'] === 'sendto') {
?>
<?php
	session_start();
	$host = isset($_POST['host']) ? $_POST['host'] : '';
	$port = isset($_POST['port']) ? $_POST['port'] : '';
	$protocol = isset($_POST['protocol']) ? $_POST['protocol'] : '';
	$url = isset($_POST['url']) ? $_POST['url'] : '';
	$request = isset($_FILES['request']['tmp_name']) ? file_get_contents($_FILES['request']['tmp_name']) : '';
	$response = isset($_FILES['response']['tmp_name']) ? file_get_contents($_FILES['response']['tmp_name']) : '';
	$comment = isset($_POST['comment']) ? $_POST['comment'] : '';
	$encoding = isset($_POST['encoding']) ? $_POST['encoding'] : '';

	$_SESSION['host'] = $host;
	$_SESSION['port'] = $port;
	$_SESSION['protocol'] = $protocol;
	$_SESSION['url'] = $url;
	$_SESSION['request'] = $request;
	$_SESSION['response'] = $response;
	$_SESSION['comment'] = $comment;
	$_SESSION['encoding'] = $encoding;

	// DBなどに保存する｡

?>
	<body>
	<a href="sendto.php?mode=disp">登録内容を確認する</a>
	</body>
<?php
} else if ($_GET['mode'] === 'disp'){
	session_start();

	// DBなどから取得する｡

?>
	<html>
	<body>
	<p><strong>disp:</strong></p>
	<p><?php echo htmlspecialchars($_SESSION['host'], ENT_QUOTES, 'UTF-8'); ?></p>
	<p><?php echo htmlspecialchars($_SESSION['port'], ENT_QUOTES, 'UTF-8'); ?></p>
	<p><?php echo htmlspecialchars($_SESSION['protocol'], ENT_QUOTES, 'UTF-8'); ?></p>
	<p><?php echo htmlspecialchars($_SESSION['url'], ENT_QUOTES, 'UTF-8'); ?></p>
	<hr>
	<p><?php echo htmlspecialchars($_SESSION['request'], ENT_QUOTES, 'UTF-8'); ?></p>
	<hr>
	<p><?php echo htmlspecialchars($_SESSION['response'], ENT_QUOTES, 'UTF-8'); ?></p>
	<hr>
	<p><?php echo htmlspecialchars($_SESSION['comment'], ENT_QUOTES, 'UTF-8'); ?></p>
	<p><?php echo htmlspecialchars($_SESSION['encoding'], ENT_QUOTES, 'UTF-8'); ?></p>
	</body>
	</html>
<?php
} else {
?>
	<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	<html>
		<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
			<title>sendto multipart/form-data</title>
		</head>
		<body>
		<!-- ########################################### -->
		<p><strong>sendto multipart/form-data(sendto.php?mode=sendto)</strong></p>
		<form action="sendto.php?mode=sendto" method="POST"	 enctype="multipart/form-data">
		<table>
		<tr><td>host</td><td><input type="text" name="host" value=""></td></tr>
		<tr><td>port</td><td><input type="text" name="port" value=""></td></tr>
		<tr><td>protocol</td><td><select name="protocol"><option value="http">http</option><option value="https">https</option></select></tr>
		<tr><td>url</td><td><input type="text" name="url" value=""></tr>
		<tr><td>comment</td><td><input type="text" name="comment" value=""></td></tr>
		<tr><td>request</td><td><input type="file" name="request" value=""></td></tr>
		<tr><td>response</td><td><input type="file" name="response" value=""></td></tr>
		<tr><td>encoding</td><td><select name="encoding"><option value="UTF-8">UTF-8<option value="Shift_JIS">Shift_JIS<option value="EUC-JP">EUC-JP<option value="ISO-2022-JP">ISO-2022-JP</select></td></tr>
		</table>
		<input type="submit">
		</form>
		</body>
	</html>
<?php
}
?>
