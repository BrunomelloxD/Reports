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

        $controllerInstance->$action((object) $_REQUEST);
    } catch (Exception $e) {
        http_response_code(500);
        echo $e->getMessage();
    }
}

// Router
$router = [
    'GET' => [
        '/get-user/' => fn () => load('UserController', 'getUser'),
        '/get-all-user/' => fn () => load('UserController', 'getAll'),
    ],
    'POST' => [
        '/create-user/' => fn () => load('UserController', 'create',),
        '/login/' => fn () => load('UserController', 'login'),
    ],
    'DELETE' => [
        '/delete-user/' => fn () => load('UserController', 'delete'),
    ],
    'PATCH' => [
        '/update-user/' => fn () => load('UserController', 'update'),
    ],
];