<?php
/* TEST */
session_start();
$mysqli = createMysqli();
$result = $mysqli->query("SELECT * FROM users WHERE login = 'admin'")->fetch_assoc();
$admin = 'admin';
$email = 'admin@site.com';
$password = '123456';

if (createUser($admin, $email, $password)) {
    echo 'Пользователь создан <br>';
}

if (login($admin, $password)) {
    echo 'Пользователь вошел <br>';
}

$user = getCurrentUser();
if (getCurrentUser()) {
    echo 'Пользователь ' . $user['email'] . ' авторизован <br>';
}

logout();
echo 'Пользователь вышел <br>';

if (getCurrentUser()) {
    echo 'Пользователь не авторизован <br>';
}


/**
 * @return mysqli
 */
function getMysqli(): mysqli
{
    return isset($GLOBALS['mysqli']) ? $GLOBALS['mysqli'] : null;
}

/* Создание подключиния к бд */
/**
 * @return mysqli
 * @throws Exception
 */
function createMysqli(): mysqli
{
    $GLOBALS['mysqli'] = new mysqli("localhost", "root", "", "example_1");
    if ($GLOBALS['mysqli']->connect_errno) {
        throw new \Exception("Не удалось подключиться к MySQL: (" . $mysqli->connect_errno . ") " . $mysqli->connect_error);
    }
    return $GLOBALS['mysqli'];
}

/**
 * Создание пользователя (регистрация)
 * @param string $login Логин пользователя (используется при входе)
 * @param string $email  Email пользователя
 * @param string $password Пароль пользователя
 * @return bool
 */
function createUser(string $login, string $email, string $password): bool
{
    $passwordToken = createPassword($password);
    return getMysqli()->query("
        INSERT INTO `users` (`login`, `email`, `token`) 
        VALUES ('$login', '$email', '$passwordToken');
        ");
}

//var_dump(createUser('admin', 'admin@admin.ru', '123456'));

/**
 * Выход из акккаунта (сброс сессий)
 */
function logout()
{
    $user = getCurrentUser();
    if ($user) {
        unset($_SESSION['userId'], $_SESSION['cookieKey']);
    }
}

/**
 * Вход (авторизация)
 * @param string $login Логин пользователя
 * @param string $password Пароль пользователя
 * @return bool
 * @throws Exception
 */
function login(string $login, string $password):bool
{
    $user = getMysqli()->query("SELECT * FROM users WHERE login = '$login'")->fetch_assoc();
    if ($user) {
        if (validatePassword( $password, $user['token'])) {
            $cookieKey = bin2hex(random_bytes(16));
            $authToken = createPassword($cookieKey);
            $updateQuery = getMysqli()->query("UPDATE users SET auth_key = '$authToken' WHERE users.id = '" . $user['id'] . "';");
            if ($updateQuery) {
                $_SESSION['userId'] = $user['id'];
                $_SESSION['cookieKey'] = $cookieKey;
                return true;
            }
        }
    }
    return false;
}

/**
 * Получить текущего авторизованного пользователя
 * @return array|null
 */
function getCurrentUser(): array
{
    if (isset($_SESSION['userId']) && isset($_SESSION['cookieKey'])) {
        $user = getUserById($_SESSION['userId']);
        if ($user) {
            if (password_verify($_SESSION['cookieKey'], $user['auth_key'])) {
                return $user;
            }
        }
    }
    return [];
}

/**
 * Валидация пароля
 * @param string $password Пароль пользователя
 * @param string $token Токен пользователя из БД
 * @return bool
 */
function validatePassword(string $password, string $token): bool
{
    return password_verify($password, $token);
}

/* Генерация пароля */
/**
 * @param string $password Создание пароля
 * @return string
 */
function createPassword(string $password): string
{
    return password_hash($password, PASSWORD_BCRYPT);
}

/**
 * Получить пользователя по его ID
 * @param int $id ID пользователя
 * @return array
 */
function getUserById(int $id): array
{
    $result = getMysqli()->query("SELECT * FROM users WHERE id = '$id'")->fetch_assoc();
    return $result ? $result : [];
}