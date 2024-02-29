<?php

namespace Bookboon\AuthBundle\Service;

use Bookboon\AuthBundle\Security\Authenticator;
use Bookboon\AuthBundle\Security\TokenGetterInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;

class TokenService
{
    public function __construct(
        private ClientRegistry $clientRegistry
    ) {
    }

    public function renewToken(?AccessTokenInterface $token): ?AccessTokenInterface
    {
        $refresh = $token?->getRefreshToken();
        if (!$refresh) {
            return null;
        }

        try {
            return $this->clientRegistry
                ->getClient(Authenticator::AUTH_PROVIDER)
                ->refreshAccessToken($refresh);
        } catch (IdentityProviderException $e) { // ignore warning that the exception is never thrown, it is
            return null;
        }
    }
}