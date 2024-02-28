<?php

namespace Bookboon\AuthBundle\Event;

use Bookboon\OauthClient\BookboonResourceOwner;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

class OauthUserEvent
{
    public function __construct(
        protected Request $request,
        protected BookboonResourceOwner $resourceOwner,
        protected AccessTokenInterface $accessToken,
        protected ?UserInterface $user = null,
    )
    {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    public function getResourceOwner(): BookboonResourceOwner
    {
        return $this->resourceOwner;
    }

    public function setResourceOwner(BookboonResourceOwner $resourceOwner): void
    {
        $this->resourceOwner = $resourceOwner;
    }

    public function getAccessToken(): AccessTokenInterface
    {
        return $this->accessToken;
    }

    public function setAccessToken(AccessTokenInterface $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }
}
