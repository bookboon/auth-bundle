<?php

namespace Bookboon\AuthBundle\DependencyInjection;

use Bookboon\AuthBundle\EventSubscriber\TokenSubscriber;
use Bookboon\AuthBundle\Grant\TokenExchangeGrant;
use Bookboon\AuthBundle\Helper\ConfigurationHolder;
use Bookboon\AuthBundle\Security\Authenticator;
use Bookboon\AuthBundle\Security\TokenGetterInterface;
use Bookboon\AuthBundle\Security\UserProvider;
use Bookboon\AuthBundle\Security\UserTokenGetter;
use Bookboon\AuthBundle\Service\TokenService;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class BookboonAuthExtension extends Extension
{
    /**
     * Loads a specific configuration.
     *
     * @param array $configs An array of configuration values
     * @param ContainerBuilder $container A ContainerBuilder instance
     *
     * @throws \InvalidArgumentException When provided tag is not defined in this extension
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $holder = $this->getConfiguration($configs, $container);
        if (!$holder) {
            throw new \InvalidArgumentException("nulled config");
        }

        $config = $this->processConfiguration($holder, $configs);

        $container->register(TokenGetterInterface::class, UserTokenGetter::class)
            ->setPublic(true)
            ->setAutowired(true);

        $container->register(Authenticator::class)
            ->setPublic(true)
            ->setBindings([
                '$rejectionRoute' => $config['rejection_route'],
                '$acceptanceRoute' => $config['acceptance_route'],
                '$authenticationRoute' => $config['authentication_route']
            ])
            ->setAutowired(true);

        $container->register(TokenService::class)
            ->setAutowired(true);

        $container->register(UserProvider::class)
            ->setAutowired(true);

        $container->register(TokenExchangeGrant::class)
            ->addTag('league.oauth2_server.authorization_server.grant')
            ->setAutowired(true);

        if ($config['handle_token_expire']) {
            $container->register(TokenSubscriber::class)
                ->addTag('kernel.event_subscriber')
                ->setAutowired(true);
        }
    }

    public function getAlias() : string
    {
        return 'bookboonauth';
    }

    public function getXsdValidationBasePath() : string
    {
        return 'http://bookboon.com/schema/dic/' . $this->getAlias();
    }
}
