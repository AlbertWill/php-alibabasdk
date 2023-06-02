<?php

namespace alibabasdk;

use alibabasdk\utils\Request;

/**
 * oauth授权
 */
class AlibabaOauth
{
    /**
     * @var string
     */
    private $oauthUrl = 'https://auth.1688.com/oauth/authorize?client_id=%s&site=1688&redirect_uri=%s&state=%s';

    /**
     * @var string
     */
    private $tokenUrl = 'https://gw.open.1688.com/openapi/http/1/system.oauth2/getToken/%s';

    /**
     * 生成授权地址
     * @param $appKey
     * @param $redirectUri
     * @param string $state
     * @return string
     */
    public function genOauthUrl($appKey, $redirectUri, string $state = 'cross-1688'):string
    {
        return sprintf($this->oauthUrl, $appKey, urlencode($redirectUri), $state);
    }

    /**
     * 授权
     * @param $appKey
     * @param $appSecret
     * @param $redirectUri
     * @param string $state
     * @return array
     * @throws AlibabaException
     */
    public function oauth($appKey, $appSecret, $redirectUri, $code): array
    {
        $res = self::accessToken($appKey, $appSecret, $redirectUri, $code);
        $data = json_decode($res, true);
        if (!array_key_exists('access_token', $data)) {
            throw new AlibabaException($data['error_description']);
        }
        return $data;
    }

    /**
     * 获取accessToken
     * @param $appKey
     * @param $appSecret
     * @param $redirect_uri
     * @param $code
     * @return bool|string
     */
    public function accessToken($appKey, $appSecret, $redirect_uri, $code)
    {
        $params = [
            'grant_type'         => 'authorization_code',
            'need_refresh_token' => true,
            'client_id'          => $appKey,
            'client_secret'      => $appSecret,
            'redirect_uri'       => $redirect_uri,
            'code'               => $code
        ];
        return Request::post(sprintf($this->tokenUrl, $appKey), $params);
    }

    /**
     * 刷新accessToken
     * @param $appKey
     * @param $appSecret
     * @param $refresh_token
     * @return bool|string
     */
    public function refreshToken($appKey, $appSecret, $refreshToken)
    {
        $params = [
            'grant_type'         => 'refresh_token',
            'client_id'          => $appKey,
            'client_secret'      => $appSecret,
            'refresh_token'       => $refreshToken,
        ];
        return Request::post(sprintf($this->tokenUrl, $appKey), $params);
    }

}
