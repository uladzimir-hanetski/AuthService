package com.example.authserver.mapper;

import com.example.authserver.dto.AuthRequest;
import com.example.authserver.entity.UserCredentials;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface AuthMapper {
    UserCredentials toEntity(AuthRequest authRequest);
}
