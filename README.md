# springsecurity
 @PostMapping(value = "/signin")
    public AuthenticationResult signin(
        @RequestBody @Valid AuthenticationRequest authenticationRequest,
        HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("signin form  data@" + authenticationRequest);
        }

        return this.handleAuthentication(
            authenticationRequest.getUsername(),
            authenticationRequest.getPassword(),
            request);
    }

    private AuthenticationResult handleAuthentication(
        String username,
        String password,
        HttpServletRequest request) {

        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
            username,
            password
        );

        final Authentication authentication = this.authenticationManager
            .authenticate(token);

        SecurityContextHolder.getContext()
            .setAuthentication(authentication);

        final HttpSession session = request.getSession(true);

        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            SecurityContextHolder.getContext()
        );

        return AuthenticationResult.builder()
            .name(authentication.getName())
            .roles(
                authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList())
            )
            .token(session.getId())
            .build();
    }
