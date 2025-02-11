package com.spring3.oauth.jwt.services;

import com.spring3.oauth.jwt.dtos.UserInfoRequest;
import com.spring3.oauth.jwt.dtos.UserInfoResponse;
import com.spring3.oauth.jwt.models.UserInfo;
import jakarta.servlet.http.HttpServletRequest;


import java.util.List;


public interface UserService {

    UserInfo saveUser(UserInfo userInfo);

    UserInfo getUser();

    List<UserInfo> getAllUser();
     String  returnClientIp(HttpServletRequest request);

    UserInfoResponse updateUser(UserInfo userInfoRequest, HttpServletRequest httpServletRequest);

    UserInfo getUserByUserName(String userName);

    UserInfo assignRole(List<String> roleIds, String userId);

    Boolean deleteUser(Long userId);

}
