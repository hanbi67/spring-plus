package org.example.expert.domain.log.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.expert.domain.common.entity.Timestamped;

@Getter
@Entity
@NoArgsConstructor
@Table(name = "log")
public class Log extends Timestamped {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String action;   // MANAGER_REGISTER

    @Column(nullable = false)
    private String status;   // REQUEST(요청 시), SUCCESS(성공 시), FAIL(실패 시)

    @Column(nullable = false)
    private Long todoId;

    @Column(nullable = false)
    private Long requesterUserId; // 요청자(일정 작성자)

    private Long targetManagerUserId; // 등록 대상

    private String message;

    public Log(String action, String status, Long todoId, Long requesterUserId, Long targetManagerUserId, String message) {
        this.action = action;
        this.status = status;
        this.todoId = todoId;
        this.requesterUserId = requesterUserId;
        this.targetManagerUserId = targetManagerUserId;
        this.message = message;
    }
}
