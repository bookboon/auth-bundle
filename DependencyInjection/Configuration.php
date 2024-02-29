<?php

namespace Bookboon\AuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('bookboonauth');

        $treeBuilder
            ->getRootNode()
            ->children()
            ->scalarNode('rejection_route')->isRequired()->end()
            ->scalarNode('acceptance_route')->isRequired()->end()
            ->scalarNode('authentication_route')->defaultValue('auth_check')->isRequired()->end()
            ->booleanNode('handle_token_expire')->defaultTrue()->end()
            ;

        return $treeBuilder;
    }
}
