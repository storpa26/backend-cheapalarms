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

        // Pass $this (Container) as argument to factory closures that expect it
        // Try calling with Container first, fallback to no args if it fails
        $factory = $this->bindings[$id];
        try {
            $this->instances[$id] = $factory($this);
        } catch (\ArgumentCountError $e) {
            // Factory doesn't expect Container parameter, call without args
            $this->instances[$id] = $factory();
        }
        
        return $this->instances[$id];
    }

    public function has(string $id): bool
    {
        return isset($this->bindings[$id]) || isset($this->instances[$id]);
    }
}

