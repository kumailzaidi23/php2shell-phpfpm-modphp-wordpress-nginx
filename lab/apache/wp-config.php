<?php
define('DB_NAME', getenv('LAB_DB_NAME'));
define('DB_USER', getenv('LAB_DB_USER'));
define('DB_PASSWORD', getenv('LAB_DB_PASSWORD'));
define('DB_HOST', getenv('LAB_DB_HOST'));
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         'local-apache-only-auth-key');
define('SECURE_AUTH_KEY',  'local-apache-only-secure-auth-key');
define('LOGGED_IN_KEY',    'local-apache-only-logged-in-key');
define('NONCE_KEY',        'local-apache-only-nonce-key');
define('AUTH_SALT',        'local-apache-only-auth-salt');
define('SECURE_AUTH_SALT', 'local-apache-only-secure-auth-salt');
define('LOGGED_IN_SALT',   'local-apache-only-logged-in-salt');
define('NONCE_SALT',       'local-apache-only-nonce-salt');

$table_prefix = 'wp_';
define('WP_HOME', getenv('LAB_ORIGIN'));
define('WP_SITEURL', getenv('LAB_ORIGIN'));
define('DISABLE_WP_CRON', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('WP_AUTO_UPDATE_CORE', false);
define('DISALLOW_FILE_MODS', true);
define('WP_DEBUG', false);

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
