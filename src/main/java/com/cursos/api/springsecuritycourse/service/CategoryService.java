package com.cursos.api.springsecuritycourse.service;

import com.cursos.api.springsecuritycourse.dto.SaveCategory;
import com.cursos.api.springsecuritycourse.persistence.entity.Category;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

public interface CategoryService {
    Page<Category> findAll(Pageable pageable);

    Optional<Category> findOneByid(Long productId);

    Category createOne(SaveCategory saveCategory);

    Category updateOneById(Long productId, SaveCategory saveCategory);

    Category disableOneById(Long productId);
}
