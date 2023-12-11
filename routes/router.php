<?php

/**
 * Loads a controller and executes the specified action.
 *
 * @param string $controller The name of the controller to load.
 * @param string $action The name of the action to execute.
 * @throws Exception If the controller or action is not found.
 * @return void
 */
function load(string $controller, string $action): void
{
    try {
        $controllerNameSpace = "app\\controllers\\" . $controller;

        if (!class_exists($controllerNameSpace)) {
            http_response_code(404);
            throw new Exception('Controller ' . $controller . ' not found');
        }

        $controllerInstance = new $controllerNameSpace();

        if (!method_exists($controllerInstance, $action)) {
            http_response_code(404);
            throw new Exception('Method ' . $action . ' not found on controller ' . $controller);
        }

        $controllerInstance->$action();
    } catch (Exception $e) {
        http_response_code(500);
        echo $e->getMessage();
    }
}

// Router
$router = [
    'GET' => [
        // User Controller
        '/get-user/' => fn () => load('UserController', 'getUser'),
        '/get-all-user/' => fn () => load('UserController', 'getAll'),
        // Report Controller
        '/get-all-report/' => fn () => load('ReportController', 'getAll'),
        // Role Controller
        '/get-all-role/' => fn () => load('RoleController', 'getAll'),
        '/get-role/' => fn () => load('RoleController', 'get'),
        // Uf Controller 
        '/get-all-uf/' => fn () => load('UfController', 'getAll'),
        '/get-uf/' => fn () => load('UfController', 'get'),

    ],
    'POST' => [
        // User Controller
        '/create-user/' => fn () => load('UserController', 'create',),
        '/login/' => fn () => load('UserController', 'login'),
        // Role Controller
        '/create-new-role/' => fn () => load('RoleController', 'create'),
        // Report Controller
        '/create-report/' => fn () => load('ReportController', 'create'),
    ],
    'DELETE' => [
        // User Controller
        '/delete-user/' => fn () => load('UserController', 'delete'),
        // Report Controller
        '/delete-report/' => fn () => load('ReportController', 'delete'),
        // Role Controller
        '/delete-role/' => fn () => load('RoleController', 'delete'),
    ],
    'PATCH' => [
        // User Controller
        '/update-user/' => fn () => load('UserController', 'update'),
        // Report Controller
        '/update-report/' => fn () => load('ReportController', 'update'),
        // Role Controller
        '/update-role/' => fn () => load('RoleController', 'update'),
    ],
];