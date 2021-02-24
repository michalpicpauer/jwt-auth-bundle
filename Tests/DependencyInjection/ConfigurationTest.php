<?php

namespace Auth0\JWTAuthBundle\Tests\DependencyInjection;

use Auth0\JWTAuthBundle\DependencyInjection\JWTAuthExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class ConfigurationTest extends TestCase
{
    private JWTAuthExtension $extension;
    private ContainerBuilder $container;
    private string $rootNode;

    public function testGetConfigWithMultipleApiIdentifiers(): void
    {
        $configs = [
            'authorized_issuer' => 'base issuer url',
            'client_secret' => 'test client secret',
            'apis' => [
                'api1' => ['audience' => 'api1'],
                'api2' => ['audience' => 'api2', 'alg' => 'HS256'],
            ],
        ];

        $this->extension->load([$configs], $this->container);

        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api1'));
        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api2'));
    }

    public function testGetConfigWithMultipleApiIdentifiersAndCache(): void
    {
        $configs = [
            'authorized_issuer' => 'base issuer url',
            'client_secret' => 'test client secret',
            'apis' => [
                'api1' => ['audience' => 'api1'],
                'api2' => ['audience' => 'api2', 'alg' => 'HS256'],
            ],
            'cache' => 'cache.app',
        ];

        $this->extension->load([$configs], $this->container);

        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api1'));
        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api2'));
    }

    public function testGetConfigWhenNotSupportedAlg(): void
    {
        $configs = [
            'authorized_issuer' => 'base issuer url',
            'apis' => [
                'api' => ['audience' => 'api', 'alg' => 'RS257'],
            ],
        ];

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('API signing algorithm is not supported: RS257');
        $this->extension->load([$configs], $this->container);
    }

    public function testGetConfigWhenMissingClientSecretForAlgHS256(): void
    {
        $configs = [
            'authorized_issuer' => 'base issuer url',
            'apis' => [
                'api' => ['audience' => 'api', 'alg' => 'HS256'],
            ],
        ];

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Client secret is missing');
        $this->extension->load([$configs], $this->container);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->extension = new JWTAuthExtension();
        $this->container = new ContainerBuilder();
        $this->rootNode = 'jwt_auth';
    }
}
