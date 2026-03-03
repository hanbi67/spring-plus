package org.example.expert.domain.user.repository;

import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.user.dto.response.UserResponse;

import java.util.List;
import java.util.Optional;

import static org.example.expert.domain.user.entity.QUser.user;
@RequiredArgsConstructor
public class UserCustomRepositoryImpl implements UserCustomRepository{

    private final JPAQueryFactory jpaQueryFactory;

    @Override
    public List<UserResponse> findByNickname(String nickname) {
        return jpaQueryFactory
                .select(Projections.constructor(
                        UserResponse.class,
                        user.id,
                        user.email
                ))
                .from(user)
                .where(user.nickname.eq(nickname))
                .fetch();
    }
}
