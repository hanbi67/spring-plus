package org.example.expert.domain.user.dto.response;

import lombok.Getter;

@Getter
public class UploadImageFileResponse {
    private final String key;

    public UploadImageFileResponse(String key) {
        this.key = key;
    }
}
