<?php

namespace DIvineOmega\LaravelPasswordSecurityAudit\Objects;

class CrackedUser
{
    public $key;
    public $password;
    public $hash;

    public function __construct($key, $password, $hash)
    {
        $this->key = $key;
        $this->password = $password;
        $this->hash = $hash;
    }
}