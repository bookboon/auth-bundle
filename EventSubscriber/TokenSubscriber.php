<?php

namespace Bookboon\AuthBundle\EventSubscriber;

use Bookboon\AuthBundle\Event\ClearTokenEvent;
use Bookboon\AuthBundle\Event\RenewTokenEvent;
use Bookboon\AuthBundle\Service\TokenService;
use Bookboon\JsonLDClient\Client\JsonLDClient;
use Bookboon\JsonLDClient\Client\JsonLDResponseException;
use Bookboon\JsonLDClient\Models\ApiError;
use Bookboon\JsonLDClient\Models\ApiErrorResponse;
use Bookboon\JsonLDClient\Models\ErrorCodes;
use GuzzleHttp\Exception\ClientException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;

class TokenSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private JsonLDClient $jsonld,
        private TokenService $service,
        private SerializerInterface $serializer,
        private EventDispatcherInterface $dispatcher,
    ) {
    }

    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::REQUEST => [
                'onKernelRequest',
                0
            ],
            KernelEvents::EXCEPTION => [
                'onKernelException',
                101 // must be before Subscriber/ExceptionSubscriber.php
            ],
            RenewTokenEvent::class => [
                'onRenewToken',
                0
            ]
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $token = $this->service->getUser()?->getAccessToken();
        if ($token) {
            $this->jsonld->setAccessToken($token);
        }
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $apiErrorResp = $this->getErrorsFromThrowable($event->getThrowable());

        // The frontend will pick up on status 401 as meaning to redirect.
        // Therefore, only send 401 status from services when the token is invalid
        if (
            $apiErrorResp &&
            count($apiErrorResp->getErrors()) > 0 &&
            ErrorCodes::isTokenError($apiErrorResp->getErrors()[0]->getCode())
        ) {
            $renewEvent = $this->dispatcher->dispatch(new RenewTokenEvent());

            // after clearing token redirect user to restart auth
            $response = new RedirectResponse($event->getRequest()->getUri());

            // If this doesn't require a full reload (ie. the refresh_token request worked), then don't
            // send status 401, which would reload the entire page, but instead just send a redirect in the ajax
            // request, which would be followed and seamlessly work
            if ($renewEvent->isFullReload() && $event->getRequest()->isXmlHttpRequest()) {
                $response = new JsonResponse(
                    $this->serializer->serialize($apiErrorResp, 'json'),
                    (int) $apiErrorResp->getErrors()[0]->getStatus(),
                    [],
                    true
                );
            }

            $event->allowCustomResponseCode();
            $event->setResponse($response);
        }
    }

    public function onRenewToken(RenewTokenEvent $event): void
    {
        $oldToken = null;
        $newToken = null;

        // This will force a re-auth, but is essentially only required for SSO
        if (null !== $user = $this->service->getUser()) {
            $oldToken = $user->getAccessToken();
            $newToken = $this->service->renewToken($oldToken);
            $event->setAccessToken($newToken);

            if ($newToken === null) {
                // See Subscriber/JsonLDSubscriber.php for how this is handled
                $event->enableFullReload();
            } else {
                $user->setAccessToken($newToken);
                $this->jsonld->setAccessToken($newToken);
            }
        }

        // For custom application implementations, such as shared token, send event that token is clearly invalid
        $this->dispatcher->dispatch(new ClearTokenEvent($oldToken, $newToken));
    }

    private function getErrorsFromThrowable(Throwable $throwable): ?ApiErrorResponse
    {
        $apiError = new ApiErrorResponse();
        $throwable = $this->unwrapThrowable($throwable);

        if ($throwable instanceof ClientException) {
            try {
                $apiError = $this->serializer->deserialize(
                    $throwable->getResponse()->getBody()->getContents(),
                    ApiErrorResponse::class,
                    'json',
                    []
                );
            } catch (\Exception $e) {
                $singleError = new ApiError();
                $singleError->setStatus((string) $throwable->getResponse()->getStatusCode());
                $apiError->setErrors([$singleError]);
            }
            return $apiError;
        }

        if ($throwable instanceof JsonLDResponseException) {
            $apiError->setErrors($throwable->getErrors());
            return $apiError;
        }

        return null;
    }

    private function unwrapThrowable(Throwable $throwable): Throwable
    {
        if ($throwable instanceof ClientException || $throwable instanceof JsonLDResponseException) {
            return $throwable;
        }

        if ($throwable->getPrevious()) {
            return $this->unwrapThrowable($throwable->getPrevious());
        }

        return $throwable;
    }
}

