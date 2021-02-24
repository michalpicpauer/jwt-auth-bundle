<?php

namespace Auth0\JWTAuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('jwt_auth');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
            ->scalarNode('domain')->end()
            ->scalarNode('client_secret')->end()
            ->arrayNode('apis')
                ->prototype('array')
                    ->children()
                        ->scalarNode('audience')->end()
                        ->scalarNode('alg')->defaultValue('RS256')->end()
                    ->end()
                ->end()
            ->end()
            ->scalarNode('cache')->defaultNull()->info('The cache service you want to use.')->end();

        return $treeBuilder;
    }
}
