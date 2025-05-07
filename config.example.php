<?php

return [
    'base_url' => 'https://localhost', // no trailing slash
    'db'       => [
        'connection' => 'sqlite',
        'dsn'        => realpath(__DIR__).'/resources/database/xbackbone.db',
        'username'   => null,
        'password'   => null,
    ],
    'storage' => [
        'driver' => 'local',
        'path'   => realpath(__DIR__).'/storage',
    ],
    'oauth' => [
        'enabled' => true,
        'name' => 'OAuth2',
        'clientId' => 'YOUR_ID_HERE',
        'clientSecret' => 'YOUR_SECRET_HERE',
        'redirectUri' => 'https://example.com/oauth/callback',
        'urlAuthorize' => 'https://auth.example.com/application/o/authorize/',
        'urlAccessToken' => 'https://auth.example.com/application/o/token/',
        'urlResourceOwnerDetails' => 'https://auth.example.com/application/o/userinfo/',
        'groups' => [
            'admin' => 'xBackBone_Admin',
            'user' => 'xBackBone_User',
        ]
    ]
];
