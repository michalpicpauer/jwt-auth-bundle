<?php

namespace Auth0\JWTAuthBundle\Tests\Functional;

use Auth0\JWTAuthBundle\JWTAuthBundle;
use Auth0\JWTAuthBundle\Security\Auth0Service;
use Nyholm\BundleTest\BaseBundleTestCase;
use Nyholm\BundleTest\CompilerPass\PublicServicePass;

class BundleInitializationTest extends BaseBundleTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        $this->addCompilerPass(new PublicServicePass());
    }

    public function testInitBundle(): void
    {
        $kernel = $this->createKernel();
        $kernel->addConfigFile(__DIR__ . '/config/jwt_auth.yml');

        // Boot kernel
        $kernel->boot();

        // Get the container
        $container = $kernel->getContainer();

        // Test if you services exists
        $this->assertTrue($container->has('jwt_auth.auth0_service'));
        $service = $container->get('jwt_auth.auth0_service');
        $this->assertInstanceOf(Auth0Service::class, $service);

        // Test if autowiring is working properly
        $this->assertTrue($container->has(Auth0Service::class));
        $service = $container->get(Auth0Service::class);
        $this->assertInstanceOf(Auth0Service::class, $service);
    }

    protected function getBundleClass(): string
    {
        return JWTAuthBundle::class;
    }
}