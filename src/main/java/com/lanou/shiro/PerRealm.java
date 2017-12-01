package com.lanou.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by dllo on 17/12/1.
 */
public class PerRealm extends AuthorizingRealm {

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
     * 授权方法
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
       //1.认证的结果:取出的User实体类/用户名
       String username = (String) principalCollection.getPrimaryPrincipal();
        //2.从数据中获取该用户的所有角色和权限
        //=====>模拟数据<======
        List<String> roleList = new ArrayList<>();
        roleList.add("CEO");
        roleList.add("HR");

        List<String> perList = new ArrayList<>();
        perList.add("user:create");
        perList.add("user:update");

        //=====>模拟结束<======
        //3.将获取的权限和角色都统一起来
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRoles(roleList);
        info.addStringPermissions(perList);

        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获得用户此次输入的用户名
        String username= (String) authenticationToken.getPrincipal();
        //此处应该拿username去查数据库是否存在该用户
        //=====>模拟<======
        if (!"wuer".equals(username)){
            throw new UnknownAccountException("用户不存在");
        }
        //=====>模拟<======

        String password = new String((char[]) authenticationToken.getCredentials()) ;
        //=====>模拟<======
        if (!"zvm".equals(password)){
            throw  new IncorrectCredentialsException("密码错误");
        }
        //===>模拟结束<=====
        //返回认证成功的信息
        return new SimpleAuthenticationInfo(username,password,getName());
    }
}
