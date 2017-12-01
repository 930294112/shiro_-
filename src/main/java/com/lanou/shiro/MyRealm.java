package com.lanou.shiro;

/**
 * Created by dllo on 17/12/1.
 */

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * 自定义Realm
 */
public class MyRealm extends AuthorizingRealm{
    //系统提供了Realm 接口,但是常用来说需要继承AuthorizingRealm
    //因为同时提供了授权和认证的方法

    @Override
    public String getName() {
        return super.getName();
    }

    /**
     *
     * 支持那种token类型  token是UsernamePasswordToken的实例才通过
     * @param token
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    /**
     * 认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获得用户此次输入的用户名
         String username= (String) authenticationToken.getPrincipal();
        //此处应该拿username去查数据库是否存在该用户
        //=====>模拟<======
        if (!"wang".equals(username)){
            throw new UnknownAccountException("用户不存在");
        }
        //===>模拟结束<=====

        String password = new String((char[]) authenticationToken.getCredentials()) ;
        //=====>模拟<======
        if (!"1234".equals(password)){
            throw  new IncorrectCredentialsException("密码错误");
        }
        //===>模拟结束<=====
        //返回认证成功的信息
        return new SimpleAuthenticationInfo(username,password,getName());
    }

}
