<?php

require_once './includes/utility.inc';

/**
 * @file
 * Configuration storage and management API.
 */


function get_signed_file_storage_names_with_prefix($prefix = '') {
  $files = glob(conf_path() . '/config/' . $prefix . '*.php');
  $clean_name = function ($value) {
    return basename($value, '.php');
  };
  return array_map($clean_name, $files);
}

function config_write_signed_file_storage_key($force_rekey = FALSE) {
  $file_path = conf_path() . '/key.php';
  if (!file_exists($file_path) || $force_rekey) {
    $key = uniqid() . uniqid() . uniqid();
    if (!file_put_contents($file_path, '<?php die(); ' . $key . "\n")) {
      throw new Exception('Failed to write configuration signing key.');
    }
  }
}

function config_sign_data($data) {
  $file = file_get_contents(conf_path() . '/key.php');
  if ($file === FALSE) {
    throw new Exception('Key file not found.');
  }
  $parts = explode(' ', $file);
  $key = $parts[2];
  // SHA-512 is both secure and very fast on 64 bit CPUs.
  return hash_hmac('sha512', $data, $key);
}

class ConfigException extends Exception {}

class ConfigFileStorageException extends ConfigException {}
class ConfigFileStorageReadException extends ConfigFileStorageException {}
class ConfigFileStorageSignatureException extends ConfigFileStorageException {}

class SignedFileStorage {
  /**
   * Constructor for the signed file storage interface.
   *
   * This class allows reading and writing configuration data from/to the
   * disk while automatically managing and verifying cryptographic signatures.
   *
   * param @name
   *   Lowercase string, the name for the configuration data.
   */
  public function __construct($name) {
    $this->name = $name;
  }

  /**
   * Read a signed file and split the content into signature and data.
   *
   * @return
   *   An array with "signature" and "data" keys.
   *
   * @throws
   *   Exception
   */
  protected function readAndSplit() {
    $content = file_get_contents($this->getFilePath());
    if (!preg_match('/^<\?php \$hash="(?P<signature>[0-9a-f]{128})"; return.(?P<data>.*);$/s', $content, $matches)) {
      throw new Exception('File has invalid header.');
    }
    return $matches;
  }

  public function getFilePath() {
    return conf_path() . '/config/' . $this->name  . '.php';
  }

  public function resign() {
    $parts = $this->readAndSplit();
    $this->write($parts['data']);
  }

  public function verify($contentOnSuccess = FALSE) {
    $split = $this->readAndSplit();
    $expected_signature = config_sign_data($split['data']);
    return ($expected_signature === $split['signature']);
  }

  public function write($data) {
    $signature = config_sign_data($data);
    $content = '<?php $hash="' . $signature . "\"; return\n" . $data .';';
    if (!file_put_contents($this->getFilePath(), $content)) {
      throw new Exception('Failed to write signed file.');
    }
  }

  public function read() {
    $verification = $this->verify(TRUE);
    if ($verification === FALSE) {
      throw new Exception('Invalid signature in file header.');
    }
    return include_once($this->getFilePath());
  }
}

interface DrupalConfigVerifiedStorageInterface {

  /**
   * Constructor for the verified storage manipulation class.
   *
   * This class allows reading and writing configuration data from/to the
   * verified storage and copying to/from the signed file storing the same
   * data.
   *
   * param @name
   *   Lowercase string, the name for the configuration data.
   */
  function __construct($name);

  /**
   * Read the configuration data from the verified storage.
   */
  function read();

  /**
   * Copy the configuration data from the verified storage into a file.
   */
  function copyToFile();

  /**
   * Copy the configuration data from the file into the verified storage.
   */
  function copyFromFile();

  /**
   * Check whether the file and the verified storage is in sync.
   *
   * @return
   *   TRUE if the file and the verified storage contains the same data, FALSE
   *   if not.
   */
  function isOutOfSync();

  /**
   * Write the configuration data into the active storage but not the file.
   *
   * Use this function if you need to make temporary changes to your
   * configuration.
   */
  function writeToActive($data);

  /**
   * Write the configuration data into the active storage and the file.
   */
  function write($data);

  /**
   * Get names starting with this prefix.
   */
  static function getNamesWithPrefix($prefix);
}

abstract class DrupalConfigVerifiedStorage implements DrupalConfigVerifiedStorageInterface {
  function __construct($name) {
    $this->name = $name;
  }

  protected function signedFileStorage() {
    return new SignedFileStorage($this->name);
  }

  public function copyTofile() {
    return $this->signedFileStorage()->write($data);
  }

  public function copyFromFile() {
    return $this->writeToActive($this->readFromFile());
  }

  public function readFromFile() {
    return $this->signedFileStorage()->read($this->name);
  }

  public function isOutOfSync() {
    return $this->read() !== $this->readFromFile();
  }

  public function write($data) {
    $this->writeToActive($data);
    $this->copyToFile();
  }
}

class DrupalVerifiedStorageSQL extends DrupalConfigVerifiedStorage {

  public function read() {
    return db_query('SELECT data FROM {config} WHERE name = :name', array(':name' => $this->name))->fetchField();
  }

  public function writeToActive($data) {
    return db_merge('config')
      ->key(array('name' => $this->name))
      ->fields(array('data' => $data))
      ->execute();
  }

  static public function getNamesWithPrefix($prefix = '') {
    return db_query('SELECT name FROM {config} WHERE name LIKE :name', array(':name' => db_like($prefix) . '%'))->fetchCol();
  }
}

function get_verified_storage_names_with_prefix($prefix = '') {
  return DrupalVerifiedStorageSQL::getNamesWithPrefix($prefix);
}

function config_get_names_with_prefix($prefix) {
  return get_verified_storage_names_with_prefix($prefix);
}

function config($name, $class = 'DrupalConfig') {
  static $overrides;
  if (!isset($overrides)) {
    $overrides = SignedFileStorage('local')->read();
  }
  // Load defaults.
  $overrides += array($name => array());
  // @TODO Replace this with the appropriate factory.
  return new $class(new DrupalVerifiedStorageSQL($name), $overrides[$name]);
}

class DrupalConfig {

  /**
   * The storage engine to save this config object to.
   *
   * @var DrupalConfigVerifiedStorageInterface
   */
  protected $_verifiedStorage;

  protected $_overrides;

  public function __construct(DrupalConfigVerifiedStorageInterface $verified_storage, $overrides = array()) {
    $this->_verifiedStorage = $verified_storage;
    $originals = $this->_verifiedStorage->read();
    $this->_overrides = $overrides;
    $active = array_merge($original_keys, $overrides);
    foreach ($active as $key => $value) {
      $this->$key = $value;
    }
  }

  public function isOverridden($key) {
    return isset($this->_overrides[$key]);
  }

  public function save() {
    $obj = new stdClass();
    foreach (get_object_vars($this) as $key => $val) {
      if ($key[0] != '_') {
        $obj->$key = $val;
      }
    }

    $this->_verifiedStorage->write(drupal_var_export($obj));
  }
}
