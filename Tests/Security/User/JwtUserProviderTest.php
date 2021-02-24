<?php

namespace Auth0\JWTAuthBundle\Tests\Security\User;

use Auth0\JWTAuthBundle\Security\User\JwtUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Tests the @see JwtUserProvider.
 */
class JwtUserProviderTest extends TestCase
{
    private JwtUserProvider $userProvider;

    public function testSupportsClass()
    {
        $this->assertTrue($this->userProvider->supportsClass(User::class));
    }

    public function testLoadUserByJWT()
    {
        $jwt = [
            'sub' => 'username',
            'token' => 'validToken',
        ];

        $expectedUser = new User('username', 'validToken', ['ROLE_JWT_AUTHENTICATED']);

        $this->assertEquals(
            $expectedUser,
            $this->userProvider->loadUserByJWT($jwt)
        );
    }

    public function testLoadUserByJWTWithoutTokenProperty()
    {
        $jwt = [
            'sub' => 'username',
        ];

        $expectedUser = new User('username', null, ['ROLE_JWT_AUTHENTICATED']);

        $this->assertEquals(
            $expectedUser,
            $this->userProvider->loadUserByJWT($jwt)
        );
    }

    public function testLoadUserByJWTWithPermissionsProperty()
    {
        $jwt = [
            'sub' => 'username',
            'permissions' => ['read:messages', 'write:messages'],
            'token' => 'validToken',
        ];

        $expectedUser = new User(
            'username',
            'validToken',
            ['ROLE_JWT_AUTHENTICATED', 'ROLE_JWT_READ_MESSAGES', 'ROLE_JWT_WRITE_MESSAGES']
        );

        $this->assertEquals(
            $expectedUser,
            $this->userProvider->loadUserByJWT($jwt)
        );
    }

    public function testGetAnonymousUser()
    {
        $this->assertContains('IS_AUTHENTICATED_ANONYMOUSLY', $this->userProvider->getAnonymousUser()->getRoles());
    }

    public function testLoadUserByUsernameWithException()
    {
        $this->expectException(UsernameNotFoundException::class);
        $this->expectExceptionMessage(
            'Auth0\JWTAuthBundle\Security\User\JwtUserProvider cannot load user "john.doe" by username. Use Auth0\JWTAuthBundle\Security\User\JwtUserProvider::loadUserByJWT instead.'
        );
        $this->userProvider->loadUserByUsername('john.doe');
    }

    public function testRefreshUser()
    {
        $user = new User('john.doe', 'validToken', ['ROLE_JWT_AUTHENTICATED']);

        $returnedUser = $this->userProvider->refreshUser($user);

        $this->assertNotSame($user, $returnedUser);
        $this->assertEquals($user, $returnedUser);
    }

    public function testRefreshUserThrowsUnsupportedUserException()
    {
        $userMock = $this->getMockBuilder(UserInterface::class)
            ->setMockClassName('UnsupportedUser')
            ->getMock();

        $this->expectException(UnsupportedUserException::class);
        $this->expectExceptionMessage('Instances of "UnsupportedUser" are not supported.');

        $this->userProvider->refreshUser($userMock);
    }

    protected function setUp(): void
    {
        $this->userProvider = new JwtUserProvider();
    }
}
