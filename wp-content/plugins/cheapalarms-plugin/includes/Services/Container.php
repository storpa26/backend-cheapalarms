<?php

namespace CheapAlarms\Plugin\Services;

class Container
{
    /**
     * @var array<string, callable>
     */
    private array $bindings = [];

    /**
     * @var array<string, mixed>
     */
    private array $instances = [];

    public function set(string $id, callable $factory): void
    {
        $this->bindings[$id] = $factory;
    }

    public function get(string $id)
    {
        if (isset($this->instances[$id])) {
            return $this->instances[$id];
        }

        if (!isset($this->bindings[$id])) {
            throw new \RuntimeException("Service {$id} not registered.");
        }

        $this->instances[$id] = ($this->bindings[$id])();
        return $this->instances[$id];
    }
}

