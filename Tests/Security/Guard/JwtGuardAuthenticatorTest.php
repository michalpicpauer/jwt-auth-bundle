<?php

namespace Auth0\JWTAuthBundle\Tests\Security\Guard;

use Auth0\JWTAuthBundle\Security\Auth0Service;
use Auth0\JWTAuthBundle\Security\Core\JWTUserProviderInterface;
use Auth0\JWTAuthBundle\Security\Guard\JwtGuardAuthenticator;
use Auth0\SDK\Exception\InvalidTokenException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Tests the @see JwtGuardAuthenticator.
 */
class JwtGuardAuthenticatorTest extends TestCase
{
    private JwtGuardAuthenticator $guardAuthenticator;

    /** @var Auth0Service|MockObject */
    private $auth0Service;

    public function testSupportsReturnsFalseWhenRequestDoesNotContainAuthorizationHeader()
    {
        $request = Request::create('/');

        $this->assertFalse($this->guardAuthenticator->supports($request));
    }

    public function testSupportsReturnsTrueWhenRequestContainsAuthorizationHeader()
    {
        $request = Request::create('/');
        $request->headers->set('Authorization', 'Bearer token');

        $this->assertTrue($this->guardAuthenticator->supports($request));
    }

    public function testGetCredentialsReturnsNullWhenRequestDoesNotContainAuthorizationHeader()
    {
        $request = Request::create('/');

        $this->assertNull($this->guardAuthenticator->getCredentials($request));
    }

    public function testGetCredentialsReturnsArrayWithJwtWhenRequestContainsAuthorizationHeader()
    {
        $request = Request::create('/');
        $request->headers->set('Authorization', 'Bearer token');

        $this->assertSame(
            ['jwt' => 'token'],
            $this->guardAuthenticator->getCredentials($request)
        );
    }

    public function testGetUserThrowsAuthenticationExceptionWhenJwtDecodingFails()
    {
        $this->auth0Service->expects($this->once())
            ->method('decodeJWT')
            ->with('invalidToken')
            ->willThrowException(new InvalidTokenException('Malformed token.'));

        $userProviderMock = $this->getMockBuilder(JWTUserProviderInterface::class)
            ->getMock();

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Malformed token.');
        $user = $this->guardAuthenticator->getUser(
            ['jwt' => 'invalidToken'],
            $userProviderMock
        );
    }

    public function testGetUserReturnsUserThroughLoadUserByJWT()
    {
        $jwt = [
            'sub' => 'authenticated-user',
            'token' => 'validToken',
        ];

        $this->auth0Service->expects($this->once())
            ->method('decodeJWT')
            ->with('validToken')
            ->willReturn($jwt);

        $user = new User($jwt['sub'], $jwt['token'], ['ROLE_JWT_AUTHENTICATED']);

        $userProviderMock = $this->getMockBuilder(JWTUserProviderInterface::class)
            ->getMock();
        $userProviderMock->expects($this->once())
            ->method('loadUserByJWT')
            ->with($jwt)
            ->willReturn($user);

        $returnedUser = $this->guardAuthenticator->getUser(
            ['jwt' => 'validToken'],
            $userProviderMock
        );

        $this->assertSame($user, $returnedUser);
    }

    public function testGetUserReturnsUserThroughLoadUserByUsername()
    {
        $jwt = [
            'sub' => 'authenticated-user',
            'token' => 'validToken',
        ];

        $this->auth0Service->expects($this->once())
            ->method('decodeJWT')
            ->with('validToken')
            ->willReturn($jwt);

        $user = new User($jwt['sub'], null, ['ROLE_JWT_AUTHENTICATED']);

        $userProviderMock = $this->getMockBuilder(UserProviderInterface::class)
            ->getMock();
        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($jwt['sub'])
            ->willReturn($user);

        $returnedUser = $this->guardAuthenticator->getUser(['jwt' => 'validToken'], $userProviderMock);

        $this->assertSame($user, $returnedUser);
    }

    public function testCheckCredentialsReturnsTrueWhenJwtDecodingSuccessful()
    {
        $this->assertTrue(
            $this->guardAuthenticator->checkCredentials(
                ['jwt' => 'validToken'],
                new User('unknown', null)
            )
        );
    }

    public function testOnAuthenticationSuccess()
    {
        $request = Request::create('/');

        $tokenMock = $this->getMockBuilder(TokenInterface::class)
            ->getMock();

        $this->assertNull(
            $this->guardAuthenticator->onAuthenticationSuccess($request, $tokenMock, 'providerKey')
        );
    }

    public function testOnAuthenticationFailure()
    {
        $request = Request::create('/');
        $exception = new AuthenticationException('Malformed token.', 0, new InvalidTokenException('Malformed token.'));

        $response = $this->guardAuthenticator->onAuthenticationFailure($request, $exception);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(JsonResponse::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertJsonStringEqualsJsonString(
            '{"message": "Authentication failed: Malformed token."}',
            $response->getContent()
        );
    }

    public function testStart()
    {
        $request = Request::create('/');

        $response = $this->guardAuthenticator->start($request);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(JsonResponse::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertJsonStringEqualsJsonString(
            '{"message": "Authentication required."}',
            $response->getContent()
        );
    }

    public function testSupportsRememberMe()
    {
        $this->assertFalse($this->guardAuthenticator->supportsRememberMe());
    }

    protected function setUp(): void
    {
        $this->auth0Service = $this->getMockBuilder(Auth0Service::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->guardAuthenticator = new JwtGuardAuthenticator($this->auth0Service);
    }
}
