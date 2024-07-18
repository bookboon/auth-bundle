<?php

namespace Bookboon\AuthBundle\Security;

use Bookboon\OauthClient\AuthServiceUser;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class UserTokenGetter implements TokenGetterInterface
{
    public function __construct(private TokenStorageInterface $tokenStorage)
    {
    }

    public function getAccessToken(): ?AccessTokenInterface
    {
        $userToken = $this->tokenStorage->getToken();
        if ($userToken && $userToken->getUser() instanceof AuthServiceUser) {
            /** @var AuthServiceUser $user */
            $user = $userToken->getUser();
            return $user->getAccessToken();
        }

        return null;
    }

    public function setAccessToken(?AccessTokenInterface $accessToken): void
    {
        $userToken = $this->tokenStorage->getToken();
        if ($userToken && $userToken->getUser() instanceof AuthServiceUser) {
            /** @var AuthServiceUser $user */
            $user = $userToken->getUser();
            $user->setAccessToken($accessToken);
        }
    }

    public function invalidate(): void
    {
        $this->tokenStorage->setToken(null); // log out user
    }
}
