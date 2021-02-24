<?php

namespace Auth0\JWTAuthBundle\Tests\Security;

use Auth0\JWTAuthBundle\Security\Auth0Service;
use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * Tests the @see Auth0Service.
 */
class Auth0ServiceTest extends TestCase
{
    public function testDecodeJWT()
    {
        $verifierMock = $this->createMock(TokenVerifier::class);
        $verifierMock->expects($this->once())
            ->method('verify')
            ->with('validToken')
            ->willReturn(['sub' => 'authenticated-user']);

        $service = new Auth0Service([$verifierMock], null);

        $this->assertEquals(['sub' => 'authenticated-user'], $service->decodeJWT('validToken'));
    }

    public function testDecodeJWTWithExceptionAnd()
    {
        $verifierMock = $this->createMock(TokenVerifier::class);
        $verifierMock->expects($this->once())
            ->method('verify')
            ->with('validToken')
            ->willThrowException(new InvalidTokenException('Exception'));

        $service = new Auth0Service([$verifierMock], null);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Any verifier could not verify the token.');
        $service->decodeJWT('validToken');
    }

    public function testDecodeJWTWithExceptionAndWithLogger()
    {
        $verifierMock = $this->createMock(TokenVerifier::class);
        $verifierMock->expects($this->once())
            ->method('verify')
            ->with('validToken')
            ->willThrowException(new InvalidTokenException('Exception'));

        $service = new Auth0Service([$verifierMock], $this->createMock(LoggerInterface::class));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Any verifier could not verify the token.');
        $service->decodeJWT('validToken');
    }
}
