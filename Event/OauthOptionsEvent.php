<?php

namespace Bookboon\AuthBundle\Event;

use Symfony\Component\HttpFoundation\Request;

class OauthOptionsEvent
{
    public function __construct(
        protected Request $request,
        protected ?array $options = null
    )
    {
    }

    public function getRequest(): Request
    {
        return $this->request;
    }

    public function setRequest(Request $request): void
    {
        $this->request = $request;
    }

    public function getOptions(): ?array
    {
        return $this->options;
    }

    public function setOptions(?array $options): void
    {
        $this->options = $options;
    }
}
