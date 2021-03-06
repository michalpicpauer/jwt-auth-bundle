<?php

namespace Auth0\JWTAuthBundle\Security\User;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface JWTUserProviderInterface extends UserProviderInterface
{
    /**
     * Loads the user for the given decoded JWT.
     *
     * This method must throw JWTInfoNotFoundException if the user is not
     * found.
     *
     * @param array $jwt The decoded Json Web Token
     *
     * @return UserInterface
     *
     * @throws AuthenticationException if the user is not found
     */
    public function loadUserByJWT(array $jwt): UserInterface;

    /**
     * Returns an anonymous user.
     *
     * This can return a JWTInfoNotFoundException exception if you don't want
     * to handle anonymous users.
     *
     * It is recommended to return a user with the role IS_AUTHENTICATED_ANONYMOUSLY
     *
     * @return UserInterface
     *
     * @throws AuthenticationException
     */
    public function getAnonymousUser(): UserInterface;
}
