package com.cursos.api.springsecuritycourse.controller;

import com.cursos.api.springsecuritycourse.dto.auth.GrantedPermissionResponse;
import com.cursos.api.springsecuritycourse.dto.auth.SaveGrantedPermission;
import com.cursos.api.springsecuritycourse.persistence.entity.security.GrantedPermission;
import com.cursos.api.springsecuritycourse.service.auth.PermissonService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/permissions")
public class PermissionController {

    @Autowired
    PermissonService permissonService;

    @GetMapping
    public ResponseEntity<Page<GrantedPermissionResponse>> findAll(Pageable pageable) {
        Page<GrantedPermissionResponse> permissionsPage = permissonService.findAll(pageable);
        if(permissionsPage.hasContent())
            return ResponseEntity.ok().body(permissionsPage);

        return ResponseEntity.notFound().build();
    }

    @GetMapping("/{permissionId}")
    public ResponseEntity<GrantedPermission> findOneById(@PathVariable Long permissionId) {
        Optional<GrantedPermission> optProduct = permissonService.findOneByid(permissionId);
        if(optProduct.isPresent())
            return ResponseEntity.ok().body(optProduct.get());

        return ResponseEntity.notFound().build();
    }

    @PostMapping
    public ResponseEntity<GrantedPermission> createOne(@RequestBody @Valid SaveGrantedPermission grantedPermission) {
        GrantedPermission newPermission = permissonService.createOne(grantedPermission);
        return ResponseEntity.status(HttpStatus.CREATED).body(newPermission);
    }

    @PutMapping("/{permissionId}")
    public ResponseEntity<GrantedPermission> updateOneById(@PathVariable Long permissionId,
                                                 @RequestBody @Valid SaveGrantedPermission grantedPermission) {
        GrantedPermission updatedPermission = permissonService.updateOneById(permissionId, grantedPermission);
        return ResponseEntity.ok(updatedPermission);
    }

    @PutMapping("/{permissionId}/delete")
    public ResponseEntity<GrantedPermission> deleteOneById(@PathVariable Long permissionId) {
        GrantedPermission deletedPermission = permissonService.deleteOneById(permissionId);
        return ResponseEntity.ok(deletedPermission);
    }
}
