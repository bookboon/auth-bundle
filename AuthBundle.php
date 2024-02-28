<?php

namespace Bookboon\AuthBundle;

use Bookboon\AuthBundle\DependencyInjection\BookboonAuthExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class AuthBundle extends Bundle
{
    public function getContainerExtension() : ?ExtensionInterface
    {
        return new BookboonAuthExtension();
    }
}
