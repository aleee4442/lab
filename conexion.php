<?php
require_once 'config.php';

class Database {
    private $host = DB_HOST;
    private $user = DB_USER;
    private $pass = DB_PASS;
    private $dbname = DB_NAME;
    
    private $connection;
    private $error;
    
    public function __construct() {
        // Crear conexión aquí
    }
    
    public function getConnection() {
        return $this->connection;
    }
}