package org.example.expert;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest
public class UserBulkInsertTest {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void bulkInsertUsers() {
        int totalCount = 5_000_000;
        int batchSize = 1000;

        String sql = "INSERT INTO users (email, password, user_role, nickname) VALUES (?, ?, ?, ?)";

        List<Object[]> batch = new ArrayList<>();

        for (int i = 1; i <= totalCount; i++) {
            batch.add(new Object[]{
                    "user" + i + "@test.com",
                    "password" + i,
                    "USER",
                    generateUniqueNickname(i)
            });

            if (i % batchSize == 0) {
                jdbcTemplate.batchUpdate(sql, batch);
                batch.clear();
                System.out.println(i + "건 완료");
            }
        }

        // 나누어 떨어지지 않는 데이터 처리
        if (!batch.isEmpty()) {
            jdbcTemplate.batchUpdate(sql, batch);
        }
    }

    private String generateUniqueNickname(int index) {
        return UUID.randomUUID().toString().substring(0, 8) + "_" + index;
    }
}
