package org.example.expert.domain.user.service;

import io.awspring.cloud.s3.S3Template;
import lombok.RequiredArgsConstructor;
import org.example.expert.config.PasswordEncoder;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.dto.request.UserChangePasswordRequest;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Presigned URL의 유효기간 설정
    private static final Duration PRESIGNED_URL_EXPIRATION = Duration.ofDays(7);

    private final S3Template s3Template;

    @Value("${spring.cloud.aws.s3.bucket}")
    private String bucket;

    public UserResponse getUser(long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new InvalidRequestException("User not found"));
        return new UserResponse(user.getId(), user.getEmail());
    }

    @Transactional
    public void changePassword(long userId, UserChangePasswordRequest userChangePasswordRequest) {
        validateNewPassword(userChangePasswordRequest);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidRequestException("User not found"));

        if (passwordEncoder.matches(userChangePasswordRequest.getNewPassword(), user.getPassword())) {
            throw new InvalidRequestException("새 비밀번호는 기존 비밀번호와 같을 수 없습니다.");
        }

        if (!passwordEncoder.matches(userChangePasswordRequest.getOldPassword(), user.getPassword())) {
            throw new InvalidRequestException("잘못된 비밀번호입니다.");
        }

        user.changePassword(passwordEncoder.encode(userChangePasswordRequest.getNewPassword()));
    }

    private static void validateNewPassword(UserChangePasswordRequest userChangePasswordRequest) {
        if (userChangePasswordRequest.getNewPassword().length() < 8 ||
                !userChangePasswordRequest.getNewPassword().matches(".*\\d.*") ||
                !userChangePasswordRequest.getNewPassword().matches(".*[A-Z].*")) {
            throw new InvalidRequestException("새 비밀번호는 8자 이상이어야 하고, 숫자와 대문자를 포함해야 합니다.");
        }
    }

    @Cacheable(value = "userCache", key = "#nickname")
    public List<UserResponse> getUserByNickname(String nickname) {
        return userRepository.findByNickname(nickname);
    }

    // 프로필 사진 업로드
    @Transactional
    public String upload(long userId, MultipartFile file) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new InvalidRequestException("존재하지 않는 사용자입니다.")
        );
        try {
            String key = "uploads/" + UUID.randomUUID() + "_" + file.getOriginalFilename();
            s3Template.upload(bucket, key, file.getInputStream());
            user.updateProfileImageUrl(key);
            return key;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 프로필 사진 Presigned URL 조회
    public URL getDownloadUrl(long userId) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new InvalidRequestException("존재하지 않는 사용자입니다.")
        );

        // 프로필 이미지 URL 존재 확인
        if (user.getProfileImageUrl() == null || user.getProfileImageUrl().isEmpty()) {
            throw new InvalidRequestException("프로필 이미지가 등록되지 않았습니다");
        }

        return s3Template.createSignedGetURL(bucket, user.getProfileImageUrl(), PRESIGNED_URL_EXPIRATION);
    }
}
