<?php

namespace Bookboon\AuthBundle\Service;

use Bookboon\AuthBundle\Security\Authenticator;
use Bookboon\OauthClient\AuthServiceUser;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class TokenService
{
    public function __construct(
        private ClientRegistry $clientRegistry,
        private TokenStorageInterface $tokenStorage
    ) {
    }

    public function getUser() : ?AuthServiceUser
    {
        $userToken = $this->tokenStorage->getToken();
        if ($userToken && $userToken->getUser() instanceof AuthServiceUser) {
            /** @var AuthServiceUser $user */
            $user = $userToken->getUser();
            return $user;
        }

        return null;
    }

    public function renewToken(?AccessTokenInterface $token): ?AccessTokenInterface
    {
        $refresh = $token?->getRefreshToken();
        if (!$refresh) {
            $this->tokenStorage->setToken(null); // log out user
            return null;
        }

        try {
            return $this->clientRegistry
                ->getClient(Authenticator::AUTH_PROVIDER)
                ->refreshAccessToken($refresh);
        } catch (IdentityProviderException $e) { // ignore warning that the exception is never thrown, it is
            $this->tokenStorage->setToken(null); // log out user
            return null;
        }
    }
}