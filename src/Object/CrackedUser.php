<?php

namespace DivineOmega\LaravelPasswordSecurityAudit\Objects;

use Illuminate\Contracts\Support\Arrayable;

class CrackedUser implements Arrayable
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

    public function toArray()
    {
        return [
            'key' => $this->key,
            'password' => $this->password,
            'hash' => $this->hash,
        ];
    }
}