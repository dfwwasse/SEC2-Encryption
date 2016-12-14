<!DOCTYPE html>
<html>
	<head>
		<title>Encrypt Dennis - Mijn dikke vette lijf.</title>
	</head>
	<body>
		<?php
			try {
				$db = new PDO('mysql:host=localhost;dbname=encrypt', 'root', 'root');
			} catch(PDOException $ex) {
				echo 'error';
			}

			$key = pack('H*', hash('sha256', $_POST['password']));
			$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);

    		function encrypt($message)
    		{
    			global $key;
				global $iv;
				global $db;

				$encryptedMessage = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $message, MCRYPT_MODE_CBC, $iv);

				$encryptedMessage  = $iv . $encryptedMessage;
				$message_base64 = base64_encode($encryptedMessage);

				$stmtInsert = $db->prepare("INSERT INTO secret (name, message) VALUES (:name, :message)");
				$stmtInsert->bindParam(':name', $_POST['name']);
				$stmtInsert->bindParam(':message', $message_base64);
				$stmtInsert->execute();

				return "Saved to database";
    		}

    		function decrypt($name)
    		{
    			global $key;
    			global $iv_size;
				global $db;

				$stmtSelect = $db->prepare("SELECT message FROM secret WHERE name = :name");
				$stmtSelect->bindParam(':name', $name);
				$stmtSelect->execute();

				if($stmtSelect->rowCount() > 0) {
					while($row = $stmtSelect->fetch()) {
						$enc_message = $row['message'];
						$enc_message_dec = base64_decode($enc_message);
						$iv_dec = substr($enc_message_dec, 0, $iv_size);

						$message_dec = substr($enc_message_dec, $iv_size);
						$message = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $message_dec, MCRYPT_MODE_CBC, $iv_dec);

						return $message;
					}
				}
    		}

    		if (isset($_POST['save']) && !empty($_POST['name']) && !empty($_POST['plaintext']) && !empty($_POST['password']))
    		{
    			$encryptMessage = encrypt($_POST['plaintext']);
    			echo $encryptMessage;
    		}
    		elseif (isset($_POST['get']) && !empty($_POST['name']) && !empty($_POST['password']))
    		{
    			$decryptMessage = decrypt($_POST['name']);
    			echo $decryptMessage;
    		}
		?>
		<h2>Encrypt-R-us</h2>
		<form method="POST">
			Name : <input type="text" name="name" /><br />
			Secret text: <textarea rows="10" name="plaintext"></textarea><br />
			Password: <input type="password" name="password" /><br />
			<input type="submit" name="save" value="Encrypt & Save" />
		</form>
		<br /><br /><br />
		<form method="POST">
			Name : <input type="text" name="name" /><br />
			Password: <input type="password" name="password" /><br />
			<input type="submit" name="get" value="Decrypt & Get" />
		</form>
	</body>
</html>
