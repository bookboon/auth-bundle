<?php

namespace Bookboon\AuthBundle\Security;

use League\OAuth2\Client\Token\AccessTokenInterface;

interface TokenGetterInterface
{
    /**
     * Get Access token from storage
     *
     * @return AccessTokenInterface|null
     */
    public function getAccessToken(): ?AccessTokenInterface;

    /**
     * Set Access token in storage
     *
     * @param AccessTokenInterface|null $accessToken
     * @return void
     */
    public function setAccessToken(?AccessTokenInterface $accessToken): void;

    /**
     * When access token is fully (including refresh) invalid
     *
     * @return void
     */
    public function invalidate(): void;
}