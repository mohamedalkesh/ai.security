package com.aisec.backend.controller;

import com.aisec.backend.dto.user.CreateUserRequest;
import com.aisec.backend.dto.user.UserDto;
import com.aisec.backend.entity.Organization;
import com.aisec.backend.entity.Role;
import com.aisec.backend.entity.UserAccount;
import com.aisec.backend.repository.OrganizationRepository;
import com.aisec.backend.repository.UserRepository;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.AuditService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN','ANALYST')")
public class UserController {

    private final UserRepository users;
    private final OrganizationRepository orgs;
    private final PasswordEncoder encoder;
    private final AuditService audit;

    public UserController(UserRepository users, OrganizationRepository orgs,
                          PasswordEncoder encoder, AuditService audit) {
        this.users = users;
        this.orgs = orgs;
        this.encoder = encoder;
        this.audit = audit;
    }

    @GetMapping
    public List<UserDto> list(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        // Always tenant-scoped: orgId=null → system users only; orgId=N → org N only.
        return users.findByOrg(orgId).stream().map(UserDto::from).toList();
    }

    @GetMapping("/{id}")
    public UserDto get(@PathVariable Long id,
                       @AuthenticationPrincipal OrgUserDetails principal) {
        UserAccount u = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        verifyOrgAccess(u, principal);
        return UserDto.from(u);
    }

    /**
     * Atomic, authenticated user creation. The new user inherits the caller's
     * organisation and is created with the requested role in a single transaction
     * — closing the bug where /api/auth/register left users orphaned (org=null)
     * and the follow-up role change failed silently.
     */
    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
    @PostMapping
    public UserDto create(@RequestBody @Valid CreateUserRequest req,
                          @AuthenticationPrincipal OrgUserDetails principal) {
        if (users.existsByUsername(req.username()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already taken");
        if (users.existsByEmail(req.email()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already taken");

        Role role;
        try { role = Role.valueOf(req.role().toUpperCase()); }
        catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid role: " + req.role());
        }

        // Resolve target organisation:
        //  - ORG_ADMIN caller   → always own org (req.organizationId is ignored)
        //  - System ADMIN caller → uses req.organizationId
        Long callerOrgId = principal != null ? principal.getOrganizationId() : null;
        Long targetOrgId;
        if (callerOrgId != null) {
            // ORG_ADMIN cannot create system ADMINs
            if (role == Role.ADMIN)
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Org admins cannot create system admins");
            targetOrgId = callerOrgId;
        } else {
            targetOrgId = req.organizationId();
        }

        // Role/org consistency:
        //  - ADMIN role  → must have org=null (system tenant)
        //  - other roles → must have a real org
        if (role == Role.ADMIN && targetOrgId != null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "System admins cannot belong to an organisation");
        if (role != Role.ADMIN && targetOrgId == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Role " + role + " requires an organisation");

        Organization org = null;
        if (targetOrgId != null) {
            org = orgs.findById(targetOrgId).orElseThrow(() ->
                    new ResponseStatusException(HttpStatus.BAD_REQUEST, "Organisation not found: " + targetOrgId));
        }

        UserAccount u = new UserAccount();
        u.setUsername(req.username());
        u.setEmail(req.email());
        u.setFullName(req.fullName());
        u.setPasswordHash(encoder.encode(req.password()));
        u.setRole(role);
        u.setOrganization(org);
        UserDto created = UserDto.from(users.save(u));
        audit.log("USER_CREATE", "USER", created.id(),
                "created user=" + created.username() + " role=" + created.role());
        return created;
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
    @PutMapping("/{id}/role")
    public UserDto changeRole(@PathVariable Long id, @RequestParam String role,
                              @AuthenticationPrincipal OrgUserDetails principal) {
        UserAccount u = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        verifyOrgAccess(u, principal);
        String oldRole = u.getRole().name();
        u.setRole(Role.valueOf(role.toUpperCase()));
        UserDto updated = UserDto.from(users.save(u));
        audit.log("USER_ROLE_CHANGE", "USER", id,
                "user=" + u.getUsername() + " " + oldRole + "->" + updated.role());
        return updated;
    }

    @PreAuthorize("hasAnyRole('ADMIN','ORG_ADMIN')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id, @AuthenticationPrincipal OrgUserDetails principal) {
        UserAccount u = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        verifyOrgAccess(u, principal);
        String deletedUsername = u.getUsername();
        users.deleteById(id);
        audit.log("USER_DELETE", "USER", id, "deleted user=" + deletedUsername);
    }

    /**
     * Strict tenant isolation — even the system owner cannot read foreign-org data.
     * orgId comparison is symmetric:
     *   caller=null and target=null → OK (both system)
     *   caller=N    and target=N    → OK
     *   anything else                → 404 (don't leak existence)
     */
    private void verifyOrgAccess(UserAccount target, OrgUserDetails principal) {
        Long myOrgId    = principal != null ? principal.getOrganizationId() : null;
        Long targetOrgId = target.getOrganization() != null ? target.getOrganization().getId() : null;
        if (!java.util.Objects.equals(myOrgId, targetOrgId))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
}
