package org.example.expert.domain.user.controller;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.dto.request.UserChangePasswordRequest;
import org.example.expert.domain.user.dto.response.FileDownloadUrlResponse;
import org.example.expert.domain.user.dto.response.UploadImageFileResponse;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URL;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/users/{userId}")
    public ResponseEntity<UserResponse> getUser(@PathVariable long userId) {
        return ResponseEntity.ok(userService.getUser(userId));
    }

    @PutMapping("/users")
    public void changePassword(@AuthenticationPrincipal AuthUser authUser, @RequestBody UserChangePasswordRequest userChangePasswordRequest) {
        userService.changePassword(authUser.getId(), userChangePasswordRequest);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getUserByNickname(@RequestParam String nickname) {
        return ResponseEntity.ok(userService.getUserByNickname(nickname));
    }

    // 프로필 이미지 업로드
    @PostMapping("/users/{userId}/profile-image")
    public ResponseEntity<UploadImageFileResponse> upload(@PathVariable long userId, @RequestParam("file") MultipartFile file) {
        String key = userService.upload(userId, file);
        return ResponseEntity.ok(new UploadImageFileResponse(key));
    }

    // 프로필 이미지 Presigned URL 조회
    @GetMapping("/users/{userId}/profile-image")
    public ResponseEntity<FileDownloadUrlResponse> getDownloadUrl(@PathVariable long userId) {
        URL url = userService.getDownloadUrl(userId);
        return ResponseEntity.ok(new FileDownloadUrlResponse(url.toString()));
    }
}
