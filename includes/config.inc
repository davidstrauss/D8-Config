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
    list($header, $data) = explode(';', $content, 2);
    if (!preg_match('/^<\?php \$hash="(?P<signature>[0-9a-f]{128})"$/', $header, $matches)) {
      throw new Exception('File has invalid header.');
    }
    return array('signature' => $matches['signature'], 'data' => $data);;
  }

  protected function exists() {
    return file_exists($this->getFilePath());
  }

  public function getFilePath() {
    return conf_path() . '/config/' . $this->name  . '.php';
  }

  public function resign() {
    if ($this->exists()) {
      $parts = $this->readAndSplit();
      $this->write($parts['data']);
    }
  }

  public function verify($contentOnSuccess = FALSE) {
    if ($this->exists()) {
      $split = $this->readAndSplit();
      $expected_signature = config_sign_data($split['data']);
      return ($expected_signature === $split['signature']);
    }
  }

  public function write($data) {
    $data = "return\n" . drupal_var_export($data) . ';';
    $signature = config_sign_data($data);
    $content = '<?php $hash="' . $signature . '";' . $data;
    if (!file_put_contents($this->getFilePath(), $content)) {
      throw new Exception('Failed to write signed file.');
    }
  }

  public function read() {
    if ($this->exists()) {
      if (!$this->verify()) {
        throw new Exception('Invalid signature in file header.');
      }
      return include_once($this->getFilePath());
    }
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
    return $this->signedFileStorage()->write($this->read());
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
    return include("drupalconfig://$this->name");
  }

  public function writeToActive($data) {
    return db_merge('config')
      ->key(array('name' => $this->name))
      ->fields(array('data' => "<?php return $data;"))
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
  // @TODO Replace this with the appropriate factory.
  return new $class($name, new DrupalVerifiedStorageSQL($name));
}

class DrupalConfig {

  /**
   * The storage engine to save this config object to.
   *
   * @var DrupalConfigVerifiedStorageInterface
   */
  protected $_verifiedStorage;

  protected $_overrides;

  public function __construct($name, DrupalConfigVerifiedStorageInterface $verified_storage) {
    $this->_verifiedStorage = $verified_storage;
    $config = $this->_verifiedStorage->read();
    // Override. Ka-boom!
    $override_file_name = conf_path() . '/local.php';
    include $override_file_name;
    foreach ($config as $key => $value) {
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

class DrupalConfigSQLStreamWrapper {
  public function stream_open($uri, $mode, $options, &$opened_url) {
    // Remove scheme
    list(, $this->name) = explode('://', $uri, 2);
    return TRUE;
  }
  public function stream_close() {}
  public function stream_read($count) {
    if (empty($this->result)) {
      $this->result = db_query('SELECT data FROM {config} WHERE name = :name', array(':name' => $this->name))->fetchField();
      $this->pos = 0;
    }
    $pos = $this->pos;
    $this->pos += $count;
    return substr($this->result, $pos, $count);
  }
  public function stream_eof() {
    return isset($this->result[$this->pos]);
  }
  public function stream_tell() {
    return $this->pos;
  }
  public function stream_stat() {
  }
}
stream_wrapper_register('drupalconfig', 'DrupalConfigSQLStreamWrapper', 0);
