<?php

namespace Auth0\JWTAuthBundle\DependencyInjection\Compiler;

use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class TokenVerifierDefinitionCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        foreach ($container->getServiceIds() as $serviceId) {
            if (!$container->hasDefinition($serviceId)) {
                continue;
            }
            $definition = $container->getDefinition($serviceId);
            $class = $definition->getClass();

            if (!$class || !class_exists($class)) {
                continue;
            }

            if ($class === TokenVerifier::class) {
                $definition->addTag('jwt_auth.token_verifier.definition');
            }
        }
    }
}
