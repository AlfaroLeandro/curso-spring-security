package com.cursos.api.springsecuritycourse.service.auth;

import com.cursos.api.springsecuritycourse.dto.auth.GrantedPermissionResponse;
import com.cursos.api.springsecuritycourse.dto.auth.SaveGrantedPermission;
import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.GrantedPermission;
import com.cursos.api.springsecuritycourse.persistence.repository.security.GrantedPermissonRepository;
import com.cursos.api.springsecuritycourse.persistence.repository.security.OperationRepository;
import com.cursos.api.springsecuritycourse.persistence.repository.security.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class PermissonService {

    @Autowired
    private GrantedPermissonRepository grantedPermissonRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private OperationRepository operationRepository;

    public Page<GrantedPermissionResponse> findAll(Pageable pageable) {
        Page<GrantedPermission> pageResult = grantedPermissonRepository.findAll(pageable);

        Page<GrantedPermissionResponse> pageResponse = pageResult.map(p -> {
            GrantedPermissionResponse dto = new GrantedPermissionResponse();
            dto.setId(p.getId());
            dto.setOperation(p.getOperation());
            dto.setRole(p.getRole().getName());
            return dto;
        });

        return pageResponse;
    }

    public Optional<GrantedPermission> findOneByid(Long permissonid) {
        return grantedPermissonRepository.findById(permissonid);
    }

    public GrantedPermission createOne(SaveGrantedPermission grantedPermission) {
        GrantedPermission permission = new GrantedPermission();
        return createUpdateGrantedPermission(grantedPermission, permission);
    }

    public GrantedPermission updateOneById(Long permissonid, SaveGrantedPermission grantedPermission) {
        GrantedPermission permission = grantedPermissonRepository.findById(permissonid)
                .orElseThrow(() -> new ObjectNotFoundException("Permission not found"));

        return createUpdateGrantedPermission(grantedPermission, permission);
    }

    @Transactional
    private GrantedPermission createUpdateGrantedPermission(SaveGrantedPermission grantedPermission, GrantedPermission permission) {
        var role = roleRepository.findById(grantedPermission.getRole())
                .orElseThrow(() -> new ObjectNotFoundException("Role not found"));
        var operation = operationRepository.findById(grantedPermission.getOperation())
                .orElseThrow(() -> new ObjectNotFoundException("Operation not found"));

        permission.setRole(role);
        permission.setOperation(operation);
        return grantedPermissonRepository.save(permission);
    }

    @Transactional
    public GrantedPermission deleteOneById(Long permissonid) {
        GrantedPermission permission = grantedPermissonRepository.findById(permissonid)
                .orElseThrow(() -> new ObjectNotFoundException("Permission not found"));

        grantedPermissonRepository.deleteById(permissonid);
        return permission;
    }
}
