package com.aisec.backend.security;

import com.aisec.backend.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public CustomUserDetailsService(UserRepository users) { this.users = users; }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var u = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        Long orgId = u.getOrganization() != null ? u.getOrganization().getId() : null;
        return new OrgUserDetails(
                u.getUsername(),
                u.getPasswordHash(),
                List.of(new SimpleGrantedAuthority("ROLE_" + u.getRole().name())),
                u.isEnabled(),
                orgId);
    }
}
