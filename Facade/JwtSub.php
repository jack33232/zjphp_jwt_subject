<?php
namespace ZJPHP\JWT\Facade;

use ZJPHP\Base\Facade;

class JwtSub extends Facade
{
    /**
     * @inheritDoc
     */
    public static function getFacadeComponentId()
    {
        return 'jwtSub';
    }
}
