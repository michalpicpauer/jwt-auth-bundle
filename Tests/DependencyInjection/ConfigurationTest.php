<?php

namespace Auth0\JWTAuthBundle\Tests\DependencyInjection;

use Auth0\JWTAuthBundle\DependencyInjection\JWTAuthExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class ConfigurationTest extends TestCase
{
    private JWTAuthExtension $extension;
    private ContainerBuilder $container;
    private string $rootNode;

    public function testGetConfigWithMultipleApiIdentifier()
    {
        $configs = [
            'domain' => 'test domain',
            'client_secret' => 'test client secret',
            'apis' => [
                'api1' => ['audience' => 'api1'],
                'api2' => ['audience' => 'api2'],
            ],
        ];

        $this->extension->load([$configs], $this->container);

        $this->assertTrue($this->container->hasParameter($this->rootNode . '.domain'));
        $this->assertTrue($this->container->hasParameter($this->rootNode . '.client_secret'));
        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api1'));
        $this->assertTrue($this->container->has($this->rootNode . '.token_verifier.api2'));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->extension = new JWTAuthExtension();
        $this->container = new ContainerBuilder();
        $this->rootNode = 'jwt_auth';
    }

//    public function testGetConfigWhenSingleApiIdentifier()
//    {
//        $configs = [
//            'api_identifier' => 'test identifier'
//        ];
//
//        $this->extension->load([$configs], $this->container);
//
//        $this->assertTrue($this->container->hasParameter($this->rootNode . '.api_identifier'));
//        $this->assertEquals('test identifier', $this->container->getParameter($this->rootNode . '.api_identifier'));
//    }
}
