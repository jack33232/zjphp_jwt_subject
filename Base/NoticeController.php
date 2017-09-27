<?php
namespace ZJPHP\JWT\Base;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Controller;
use Klein\Exceptions\HttpException;
use ZJPHP\Facade\ZJRedis;
use ZJPHP\JWT\Facade\Authentication;
use ZJPHP\Facade\Security;

class NoticeController extends Controller
{
    /**
     * Call authentication service to assign a JWT
     * Request need to be signed & Replay defender need to be activated.
     **/
    public function jwt($request, $response, $service, $app, $router)
    {
        $jti = $request->paramsPost()->get('jti', null);
        $expire_at = $request->paramsPost()->get('expire_at', null);

        if (empty($jti) || empty($expire_at)) {
            throw HttpException::createFromCode(400);
        }
        Authentication::acceptJwt($jti, $expire_at);

        $flag_for_sign = $request->paramsPost()->get('sign', 'N');
        $flag_for_encrypt = $request->paramsPost()->get('encrypt', 'N');

        $result = [
            'success' => true
        ];
        if ($flag_for_sign === 'Y' || $flag_for_encrypt === 'Y') {
            $session_key = Authentication::genSessionKey($jti, $expire_at);
            $result['session_key'] = Security::asymmetricEncrypt($session_key);
        }

        $response->apiJson($result);
    }
}
