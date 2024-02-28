<?php

namespace Bookboon\AuthBundle\Event;

use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * This event is sent to indicate that the token is now fully invalid and cannot be refreshed.
 */
class ClearTokenEvent extends Event
{
    public function __construct(
        protected ?AccessTokenInterface $oldAccessToken,
        protected ?AccessTokenInterface $newAccessToken
    ) {
    }

    public function getOldAccessToken(): ?AccessTokenInterface
    {
        return $this->oldAccessToken;
    }

    public function getNewAccessToken(): ?AccessTokenInterface
    {
        return $this->newAccessToken;
    }
}
