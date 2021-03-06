<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use Klein\Exceptions\HttpException;
use ZJPHP\JWT\Facade\JwtSub;
use ZJPHP\Base\Kit\StringHelper;

class JWT extends Component implements FilterInterface
{
    protected $audience = BASE_URL;

    public function filter($request, $response, $service, $app, $router)
    {
        $jwt_str = trim(substr($request->headers()->get('Authorization'), strlen(JwtSub::getJwtSchema())));

        $app->jwt = $jwt = JwtSub::verifyJwt($jwt_str, $this->audience);

        $jti = $jwt->getHeader('jti');
        $sign = $jwt->getClaim('sign', 'N');
        $encrypt = $jwt->getClaim('encrypt', 'N');
        $expire_at = $jwt->getClaim('exp', strtotime('2047-06-30 23:59:59'));

        if ($sign === 'Y' || $encrypt === 'Y') {
            $session_key = JwtSub::getSessionKey($jti, $expire_at);
            if (empty($session_key)) {
                throw HttpException::createFromCode(401);
            }
            $app->session_key = $session_key;
            if ($encrypt === 'Y') {
                $response->encrypt = true;
                $response->password = $session_key;
            }
        }
        $app->encrypt = $encrypt === 'Y';
        $app->sign = $sign === 'Y';
    }

    public function setAudience($audience)
    {
        $this->audience = $audience;
    }
}
