<?php

namespace Auth0\JWTAuthBundle\Security\Core;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JWTInfoNotFoundException extends AuthenticationException
{
    private string $jwt;

    public function getJWT(): string
    {
        return $this->jwt;
    }

    public function setJWT(string $jwt): void
    {
        $this->jwt = $jwt;
    }

    public function getMessageKey(): string
    {
        return 'JWT could not be found.';
    }

    public function serialize(): string
    {
        return serialize(
            [
                $this->jwt,
                parent::serialize(),
            ]
        );
    }

    public function unserialize($str): void
    {
        [$this->jwt, $parentData] = unserialize($str);

        parent::unserialize($parentData);
    }

    public function getMessageData(): array
    {
        return ['{{ jwt }}' => $this->jwt];
    }
}
