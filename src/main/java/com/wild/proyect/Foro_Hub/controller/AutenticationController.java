package com.wild.proyect.Foro_Hub.controller;

import com.wild.proyect.Foro_Hub.domain.user.DatosAutenticationUsuario;
import com.wild.proyect.Foro_Hub.domain.user.Usuario;
import com.wild.proyect.Foro_Hub.infra.security.DatosJwtToken;
import com.wild.proyect.Foro_Hub.infra.security.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("login")
public class AutenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    @PostMapping
    public ResponseEntity autenticarUsuario(@RequestBody @Valid DatosAutenticationUsuario datosAutenticacionUsuario) {
        Authentication authToken = new UsernamePasswordAuthenticationToken(datosAutenticacionUsuario.login(),
                datosAutenticacionUsuario.password());
        var usuarioAutenticado = authenticationManager.authenticate(authToken);
        var JwtToken = tokenService.generateToken((Usuario) usuarioAutenticado.getPrincipal());
        return ResponseEntity.ok(new DatosJwtToken(JwtToken));
    }
}
