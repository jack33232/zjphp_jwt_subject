<?php
namespace ZJPHP\JWT\Service;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Facade\Security;
use ZJPHP\Facade\ZJRedis;
use ZJPHP\Base\Exception\InvalidConfigException;
use ZJPHP\Base\Exception\InvalidCallException;
use ZJPHP\Base\Exception\InvalidParamException;
use ZJPHP\Base\Exception\DatabaseErrorException;
use Klein\Exceptions\HttpException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class JwtSub extends Component
{
    private $_jwtRsa = [];
    private $_jwtIssuer = BASE_URL;
    private $_jwtSchema = 'Bearer';
    private $_jwtPoolThreshold = 5000;

    public function sign($data, $secret)
    {
        if (isset($data['signature'])) {
            unset($data['signature']);
        }

        ksort($data, SORT_NATURAL);
        $data_string = http_build_query($data, '', '&', PHP_QUERY_RFC3986);

        return Security::hash($data_string, 'sha256', $secret, false);
    }

    public function rsaSign($data, $base_url = '')
    {
        ksort($data, SORT_NATURAL);
        $data_string = $base_url . '?' . http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        return Security::genDigitalSignature($data_string);
    }

    public function rsaVerify($data, $expected, $base_url = '')
    {
        ksort($data, SORT_NATURAL);
        $data_string = $base_url . '?' . http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        return Security::verifyDigitalSignature($data_string, $expected);
    }

    public function acceptJwt($jti, $expire_at)
    {
        $jwt_pool_key = $this->_getJwtPoolKey();
        $redis_client = ZJRedis::connect();

        $result = $redis_client->zAdd($jwt_pool_key, $expire_at, $jti);

        if ($redis_client->zSize($jwt_pool_key)
            > $this->_jwtPoolThreshold) {
            $redis_client->zRemRangeByScore($jwt_pool_key, 0, time() - 1);
        }

        if ($result === false) {
            throw new DatabaseErrorException('Fail to accept JWT, pls retry.', 5001);
        }
    }

    public function genSessionKey($jti, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        $existed = $redis_client->exists($session_key_pool_key);
        $session_key = Security::generateRandomString(16);
        $redis_client->hSet($session_key_pool_key, $jti, $session_key);
        if (!$existed) {
            $pool_expire_at = date('Y-m-d 23:59:59', $expire_at);
            $redis_client->expireAt($session_key_pool_key, strtotime($pool_expire_at));
        }

        return $session_key;
    }

    public function subSaveSessionKey($jti, $session_key, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        $existed = $redis_client->exists($session_key_pool_key);
        $redis_client->hSet($session_key_pool_key, $jti, $session_key);
        if (!$existed) {
            $pool_expire_at = date('Y-m-d 23:59:59', $expire_at);
            $redis_client->expireAt($session_key_pool_key, strtotime($pool_expire_at));
        }

        return $session_key;
    }

    public function getSessionKey($jti, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        if ($redis_client->exists($session_key_pool_key)
            && $redis_client->hExists($session_key_pool_key, $jti)
        ) {
            return $redis_client->hGet($session_key_pool_key, $jti);
        } else {
            return null;
        }
    }

    public function verifyJwt($jwt_str, $audience)
    {
        try {
            $jwt = (new Parser())->parse((string) $jwt_str);
        } catch (\Exception $e) {
            throw HttpException::createFromCode(401);
        }
        $this->verifyJwtSignature($jwt);
        $this->verifyJwtClaims($jwt, $audience);
        $this->verifyJwtRovoke($jwt);

        return $jwt;
    }

    public function simpleVerifyJwt($jwt_str, $audience)
    {
        try {
            $jwt = (new Parser())->parse((string) $jwt_str);
        } catch (\Exception $e) {
            throw HttpException::createFromCode(401);
        }
        $this->verifyJwtSignature($jwt);
        $this->verifyJwtClaims($jwt, $audience);

        return $jwt;
    }

    public function subVerifyJwt($jwt_str)
    {
        try {
            $jwt = (new Parser())->parse((string) $jwt_str);
        } catch (\Exception $e) {
            throw HttpException::createFromCode(401);
        }
        $this->verifyJwtSignature($jwt);

        return $jwt;
    }

    protected function verifyJwtRovoke($jwt)
    {
        $jti = $jwt->getHeader('jti');
        $jwt_pool_key = $this->_getJwtPoolKey();

        $redis_client = ZJRedis::connect();
        $existed = $redis_client->zScore($jwt_pool_key, $jti);
        if (is_null($existed) || $existed === false) {
            throw HttpException::createFromCode(401);
        }
    }

    protected function verifyJwtSignature($jwt)
    {
        $signer = new Sha256();

        $keychain = new Keychain();

        $result = $jwt->verify($signer, $keychain->getPublicKey($this->_jwtRsa['publicKey']));

        if ($result === false) {
            throw HttpException::createFromCode(401);
        }
    }

    protected function verifyJwtClaims($jwt, $audience)
    {
        $data = new ValidationData();
        $data->setIssuer($this->_jwtIssuer);
        $data->setAudience($audience);

        $result = $jwt->validate($data);
        if ($result === false) {
            throw HttpException::createFromCode(401);
        }
    }

    private function _getJwtPoolKey()
    {
        return ZJPHP::$app->getAppName() . ':JwtPool';
    }

    private function _getJwtSessionKeyPoolKey($expire_at)
    {
        return ZJPHP::$app->getAppName() . ':JwtSessionKeyPool-' . date('Ymd', $expire_at);
    }


    public function setJwtRsa($rsa_setting)
    {
        if (!isset($rsa_setting['publicKey'])) {
            throw new InvalidConfigException('RSA Setting incorrect.');
        }
        $this->_jwtRsa = $rsa_setting;
    }

    public function setJwtIssuer($issurer)
    {
        $this->_jwtIssuer = $issurer;
    }

    public function setJwtSchema($schema)
    {
        $this->_jwtSchema = $schema;
    }

    public function setJwtPoolThreshold($number)
    {
        if (is_numeric($number) && $number > 100 && $number < 10000) {
            $this->_jwtPoolThreshold = $number;
        }
    }

    public function getJwtSchema()
    {
        return $this->_jwtSchema;
    }
}
