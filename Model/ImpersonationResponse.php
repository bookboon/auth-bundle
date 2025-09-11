<?php

namespace Bookboon\AuthBundle\Model;

use Bookboon\OauthClient\BookboonResourceOwner;
use League\OAuth2\Client\Token\AccessTokenInterface;

class ImpersonationResponse
{
    public function __construct(
        private AccessTokenInterface $token,
        private BookboonResourceOwner $resourceOwner,
    )
    {
    }

    public function getToken(): AccessTokenInterface
    {
        return $this->token;
    }

    public function getResourceOwner(): BookboonResourceOwner
    {
        return $this->resourceOwner;
    }
}
