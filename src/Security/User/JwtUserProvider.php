<?php

namespace Auth0\JWTAuthBundle\Security\User;

use Auth0\JWTAuthBundle\Security\Core\JWTUserProviderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Basic JWT UserProvider implementation when you do not require loading the user from the database and
 * the JWT verification with Auth0 is enough for your use-case. Eg. Machine-to-Machine authentication.
 */
class JwtUserProvider implements JWTUserProviderInterface
{
    public function supportsClass($class): bool
    {
        return $class === User::class;
    }

    public function loadUserByJWT(array $jwt): UserInterface
    {
        $token = $jwt['token'] ?? null;

        return new User($jwt['sub'], $token, $this->getRoles($jwt));
    }

    public function getAnonymousUser(): UserInterface
    {
        return new User('anonymous', null, ['IS_AUTHENTICATED_ANONYMOUSLY']);
    }

    public function loadUserByUsername($username): UserInterface
    {
        throw new UsernameNotFoundException(
            sprintf(
                '%1$s cannot load user "%2$s" by username. Use %1$s::loadUserByJWT instead.',
                __CLASS__,
                $username
            )
        );
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if ($user instanceof User === false) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return new User($user->getUsername(), $user->getPassword(), $user->getRoles());
    }

    /**
     * Returns the roles for the user.
     */
    private function getRoles(array $jwt): array
    {
        return array_merge(
            [
                'ROLE_JWT_AUTHENTICATED',
            ],
            $this->getScopesFromJwtAsRoles($jwt)
        );
    }

    /**
     * Returns the scopes from the JSON Web Token as Symfony roles prefixed with 'ROLE_JWT_SCOPE_'.
     */
    private function getScopesFromJwtAsRoles(array $jwt): array
    {
        if (isset($jwt['scope']) === false) {
            return [];
        }

        $scopes = explode(' ', $jwt['scope']);
        return array_map(
            function ($scope) {
                $roleSuffix = strtoupper(str_replace([':', '-'], '_', $scope));

                return sprintf('ROLE_JWT_SCOPE_%s', $roleSuffix);
            },
            $scopes
        );
    }
}
