package com.cursos.api.springsecuritycourse.dto.auth;

import com.cursos.api.springsecuritycourse.persistence.entity.security.Operation;

import java.io.Serializable;

public class GrantedPermissionResponse implements Serializable {

    private Long id;

    private String role;

    private Operation operation;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Operation getOperation() {
        return operation;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }
}
