<?php

namespace Bookboon\AuthBundle\Grant;

use League\OAuth2\Client\Grant\AbstractGrant;

class TokenExchangeGrant extends AbstractGrant
{

    protected function getName()
    {
        return "urn:ietf:params:oauth:grant-type:token-exchange";
    }

    protected function getRequiredRequestParameters()
    {
        return [
            'subject_token',
            'subject_token_type',
        ];
    }
}
