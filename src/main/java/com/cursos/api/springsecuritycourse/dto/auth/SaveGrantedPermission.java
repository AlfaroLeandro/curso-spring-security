package com.cursos.api.springsecuritycourse.dto.auth;

import jakarta.validation.constraints.Min;

import java.io.Serializable;

public class SaveGrantedPermission implements Serializable {

    @Min(value = 1)
    private Long role;

    @Min(value = 1)
    private Long operation;

    public Long getRole() {
        return role;
    }

    public void setRole(Long role) {
        this.role = role;
    }

    public Long getOperation() {
        return operation;
    }

    public void setOperation(Long operation) {
        this.operation = operation;
    }
}
