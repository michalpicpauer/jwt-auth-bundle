<?php

namespace Auth0\JWTAuthBundle\Security\Guard;

use Auth0\JWTAuthBundle\Security\Auth0Service;
use Auth0\JWTAuthBundle\Security\Core\JWTUserProviderInterface;
use Auth0\SDK\Exception\CoreException;
use Auth0\SDK\Exception\InvalidTokenException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * Handles authentication with JSON Web Tokens through the 'Authorization' request header.
 */
class JwtGuardAuthenticator extends AbstractGuardAuthenticator
{
    private Auth0Service $auth0Service;

    public function __construct(Auth0Service $auth0Service)
    {
        $this->auth0Service = $auth0Service;
    }

    public function supports(Request $request): bool
    {
        return $request->headers->has('Authorization')
            && strpos($request->headers->get('Authorization'), 'Bearer') === 0;
    }

    public function getCredentials(Request $request): ?array
    {
        // Removes the 'Bearer ' part from the Authorization header value.
        $jwt = str_replace('Bearer ', '', $request->headers->get('Authorization', ''));

        if (empty($jwt)) {
            return null;
        }

        return [
            'jwt' => $jwt,
        ];
    }

    /**
     * Returns a user based on the information inside the JSON Web Token depending on the implementation
     * of the configured user provider.
     *
     * When the user provider does not implement the JWTUserProviderInterface it will attempt to load
     * the user by username with the 'sub' (subject) claim of the JSON Web Token.
     *
     * @param array $credentials
     */
    public function getUser($credentials, UserProviderInterface $userProvider): ?UserInterface
    {
        try {
            $jwt = $this->auth0Service->decodeJWT($credentials['jwt']);
        } catch (InvalidTokenException $exception) {
            throw new AuthenticationException($exception->getMessage(), $exception->getCode(), $exception);
        }

        if (!isset($jwt['token'])) {
            $jwt['token'] = $credentials['jwt'];
        }

        if ($userProvider instanceof JWTUserProviderInterface) {
            return $userProvider->loadUserByJWT($jwt);
        }

        return $userProvider->loadUserByUsername($jwt['sub']);
    }

    /**
     * Returns true when the provided JSON Web Token successfully decodes and validates.
     *
     * @param array $credentials
     *
     * @throws AuthenticationException when decoding and/or validation of the JSON Web Token fails
     */
    public function checkCredentials($credentials, UserInterface $user): bool
    {
        // already checked by getUser
        return true;
    }

    /**
     * Returns nothing to continue the request when authenticated.
     *
     * @param string $providerKey
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        return null;
    }

    /**
     * Returns the 'Authentication failed' response.
     *
     * @param Request $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $responseBody = [
            'message' => sprintf(
                'Authentication failed: %s.',
                rtrim($exception->getMessage(), '.')
            ),
        ];

        return new JsonResponse($responseBody, JsonResponse::HTTP_UNAUTHORIZED);
    }

    /**
     * Returns a response that directs the user to authenticate.
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $responseBody = [
            'message' => 'Authentication required.',
        ];

        return new JsonResponse($responseBody, JsonResponse::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe(): bool
    {
        return false;
    }
}
