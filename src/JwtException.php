<?php


namespace Jdmm\Jwt;
/**
 * Class JwtException
 * @package Jdmm\Jwt 异常类
 */
class JwtException extends \Exception
{
    //权限认证失败
    const AUTH_FAIL        = 401;
    //数据来源认证失败
    const DATA_SOURCE_FAIL = 402;
    //认证过期
    const AUTH_EXPIRE      = 404;
}