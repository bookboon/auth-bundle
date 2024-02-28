<?php

namespace Bookboon\AuthBundle\Security;

use Bookboon\AuthBundle\Service\TokenService;
use Bookboon\OauthClient\AuthServiceUser;
use RuntimeException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface
{
    public function __construct(
        protected TokenService $service
    ) {
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof AuthServiceUser) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        $accessToken = $user->getAccessToken();

        if ($accessToken &&
            $accessToken->hasExpired() &&
            null === $this->service->renewToken($accessToken)
        ) {
            // Return empty user because that will trigger user being invalidated and
            // a new oauth2 flow will start
            return new AuthServiceUser();
        }

        return $user;
    }

    public function supportsClass($class): bool
    {
        return $class === AuthServiceUser::class || is_subclass_of($class, AuthServiceUser::class);
    }

    public function loadUserByUsername($username): AuthServiceUser
    {
        return new AuthServiceUser();
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new RuntimeException('should not be called');
    }
}
