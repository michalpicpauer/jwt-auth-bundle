<?php

namespace Auth0\JWTAuthBundle\Security;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Psr\Log\LoggerInterface;

class Auth0Service
{
    /** @var iterable|TokenVerifier[] */
    private iterable $tokenVerifiers;

    private ?LoggerInterface $logger;

    public function __construct(iterable $tokenVerifiers, ?LoggerInterface $logger)
    {
        $this->tokenVerifiers = $tokenVerifiers;
        $this->logger = $logger;
    }

    /**
     * Decodes the JWT and validate it
     * @throws InvalidTokenException
     */
    public function decodeJWT(string $encodedToken): array
    {
        foreach ($this->tokenVerifiers as $verifier) {
            try {
                return $verifier->verify($encodedToken);
            } catch (InvalidTokenException $e) {
                $this->logMessage(
                    'Verifier was unable to verify the token. {message}',
                    ['message' => $e->getMessage()]
                );
            }
        }

        throw new InvalidTokenException('Any verifier could not verify the token.');
    }

    private function logMessage(string $message, array $context)
    {
        if (!$this->logger) {
            return;
        }

        $this->logger->info($message, $context);
    }
}
