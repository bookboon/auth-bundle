<?php

namespace Bookboon\AuthBundle\Event;

use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * This event is sent to indicate that the token is expired and refresh flow will be attempted
 */
class RenewTokenEvent extends Event
{
    protected bool $fullReload = false;
    protected ?AccessTokenInterface $accessToken = null;

    public function enableFullReload(): void
    {
        $this->fullReload = true;
    }

    public function isFullReload(): bool
    {
        return $this->fullReload;
    }

    public function getAccessToken(): ?AccessTokenInterface
    {
        return $this->accessToken;
    }

    public function setAccessToken(?AccessTokenInterface $accessToken): void
    {
        $this->accessToken = $accessToken;
    }
}
