<?php
namespace Jdmm\Jwt;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;

/**
 * Class Jwt
 * @package Jdmm\Jwt
 */
class Jwt
{
    private static $builder;
    private static $signer;
    private static $parser;

    /**
     * Jwt constructor.
     */
    public static function __init()
    {
        self::$builder      = empty(self::$builder) ? new Builder(): self::$builder ;
        self::$signer       = empty(self::$signer) ? new Sha256(): self::$signer ;
        self::$parser       = empty(self::$parser ) ? new Parser(): self::$parser ;
    }

    /**
     * @param array $data
     * @param string $secret
     * @return string
     */
    public static function encode(array $data ,string $secret) : string
    {
        self::__init();
        //设置header和payload，以下的字段都可以自定义
        self::$builder
            //发布者
            //->setIssuer($this->issuer)
            //header密文
            ->setHeader('alg','HS256')
            //接收者
            //->setAudience($this->audience)
            //对当前token设置的标识
            //->setId("abc", true)
            //token创建时间
            ->issuedAt(new \DateTimeImmutable("now"));
            //过期时间
            //->setExpiration($time + $expire_time)
            //当前时间在这个时间前，token不能使用
            //->setNotBefore($time + 5);
        //处理数据 支持一纬数组
        self::setData($data);
        //设置签名
//        self::$builder->sign();
        //获取加密后的token，转为字符串
        return (string)self::$builder->getToken(self::$signer, new Key($secret));

    }

    /**
     * @param string $token
     * @param string $secret
     * @return array
     * @throws JwtException
     */
    public static function decode(string $token,string $secret) : array
    {
        self::__init();
        //初始化
        $parse = self::$parser->parse($token);
        //验证token合法性
        if (!$parse->verify(self::$signer, new Key($secret))) throw new JwtException('权限认证失败',JwtException::AUTH_FAIL);

        //数据来源的验证
        // if (($parse->getClaim('iss') !== $this->issuer) || ($parse->getClaim('aud') !== $this->audience)) throw new JwtException('来源认证失败',JwtException::DATA_SOURCE_FAIL);

        //验证是否已经过期
        //if ($parse->isExpired()) throw new JwtException('权限认证已经过期',JwtException::AUTH_EXPIRE);
        //初始化数据
        return self::initData($parse->getClaims());

    }

    private static function setData(array $data)
    {
        foreach ($data as $k => $v){
            self::$builder->set($k,$v);
        }
    }

    private static function initData($data)
    {
        return json_decode(json_encode($data),true);
    }
}
