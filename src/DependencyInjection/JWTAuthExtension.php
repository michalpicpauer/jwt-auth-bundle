<?php

namespace Auth0\JWTAuthBundle\DependencyInjection;

use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class JWTAuthExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');
        $container->setParameter('jwt_auth.domain', $config['domain']);
        $container->setParameter('jwt_auth.client_secret', $config['client_secret'] ?? '');

        $cacheService = null;
        if (isset($config['cache']) && $container->has($config['cache'])) {
            $cacheService = $container->get($config['cache']);
            if (!$cacheService instanceof CacheInterface) {
                $cacheService = null;
            }
        }
        $apis = $config['apis'] ?? [];
        foreach ($apis as $name => $api) {
            if ($api['alg'] === 'RS256') {
                $signatureVerifier = new AsymmetricVerifier(new JWKFetcher($cacheService));
            } elseif ($api['alg'] === 'HS256') {
                if (!isset($config['client_secret'])) {
                    throw new InvalidConfigurationException('Client secret is missing.');
                }

                $signatureVerifier = new SymmetricVerifier($config['client_secret']);
            } else {
                throw new InvalidConfigurationException('API signing algorithm is not supported: ' . $api['alg']);
            }

            $serviceId = 'jwt_auth.token_verifier.' . $name;
            $tokenVerifier = new TokenVerifier($config['domain'], $api['audience'], $signatureVerifier);
            $container->set($serviceId, $tokenVerifier);
        }

        if (!empty($config['cache'])) {
            $ref = new Reference($config['cache']);
            $container->getDefinition('jwt_auth.auth0_service')
                ->replaceArgument(6, $ref);
        }
    }
}
