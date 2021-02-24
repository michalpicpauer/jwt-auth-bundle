<?php

namespace Auth0\JWTAuthBundle\DependencyInjection;

use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
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

        $cacheService = null;
        if (isset($config['cache'])) {
            $cacheService = new Reference($config['cache']);
        }

        $apis = $config['apis'] ?? [];
        foreach ($apis as $name => $api) {
            if ($api['alg'] === 'RS256') {
                $signatureVerifierDefinition = new Definition(
                    AsymmetricVerifier::class,
                    [
                        new Definition(
                            JWKFetcher::class,
                            [
                                $cacheService,
                                ['base_uri' => $config['authorized_issuer'] . '.well-known/jwks.json'],
                            ]
                        ),
                    ]
                );
            } elseif ($api['alg'] === 'HS256') {
                if (!isset($config['client_secret'])) {
                    throw new InvalidConfigurationException('Client secret is missing');
                }

                $signatureVerifierDefinition = new Definition(SymmetricVerifier::class, [$config['client_secret']]);
            } else {
                throw new InvalidConfigurationException('API signing algorithm is not supported: ' . $api['alg']);
            }

            $serviceId = 'jwt_auth.token_verifier.' . $name;
            $definition = new Definition(
                TokenVerifier::class,
                [$config['authorized_issuer'], $api['audience'], $signatureVerifierDefinition]
            );
            $definition->addTag('jwt_auth.token_verifier.definition');
            $container->setDefinition($serviceId, $definition);
        }
    }
}
