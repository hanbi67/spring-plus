package org.example.expert.domain.user.repository;

import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.entity.User;

import java.util.List;
import java.util.Optional;

public interface UserCustomRepository {
    List<UserResponse> findByNickname(String nickname);
}
