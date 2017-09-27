<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use Klein\Exceptions\HttpException;
use ZJPHP\JWT\Facade\Authentication;

class Signature extends Component implements FilterInterface
{
    public function filter($request, $response, $service, $app, $router)
    {
        if (isset($app->sign)) {
            if ($app->sign === true) {
                $this->verifyQuietMode($request, $response, $service, $app, $router);
            }
        }
    }

    protected function verifyQuietMode($request, $response, $service, $app, $router)
    {
        // Process request data
        $request_data = $request->paramsPost()->all();

        // Validate request data
        $validate_result = (!empty($request_data['signature'])
            && is_string($request_data['signature'])
        );

        if ($validate_result === false) {
            throw HttpException::createFromCode(400);
        }

        // Verify the user signature
        $signature = Authentication::sign($request_data, $app->session_key);
        if ($request_data['signature'] !== $signature) {
            throw HttpException::createFromCode(401);
        }
    }
}
