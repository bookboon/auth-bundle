<?php

namespace Bookboon\AuthBundle\Tests\Security;

use Bookboon\AuthBundle\Security\UserProvider;
use Bookboon\AuthBundle\Service\TokenService;
use Bookboon\OauthClient\AuthServiceUser;
use PHPUnit\Framework\TestCase;

class UserProviderTest extends TestCase
{
    public function testSupportsDirect()
    {
        $service = self::createMock(TokenService::class);
        $provider = new UserProvider($service);

        self::assertTrue($provider->supportsClass(AuthServiceUser::class));
    }

    public function testSupportsImplemented()
    {
        $service = self::createMock(TokenService::class);
        $provider = new UserProvider($service);

        self::assertTrue($provider->supportsClass(TestAuthServiceUser::class));
    }
}
