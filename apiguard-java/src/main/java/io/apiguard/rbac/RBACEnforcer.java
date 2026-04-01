package io.apiguard.rbac;

import io.jsonwebtoken.Claims;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * AOP aspect that enforces {@link RequiresPermission} on controller methods.
 * Reads {@link Claims} stored by {@link io.apiguard.filter.SecurityFilter}
 * as a request attribute and checks whether the required permission is present.
 */
@Aspect
@Component
public class RBACEnforcer {

    /**
     * Intercepts any method annotated with {@link RequiresPermission}
     * and verifies the caller holds the declared permission.
     *
     * @throws AccessDeniedException if the permission is absent
     */
    @Around("@annotation(requiredPermission)")
    public Object enforce(ProceedingJoinPoint pjp,
                          RequiresPermission requiredPermission) throws Throwable {

        Claims claims = extractClaims();

        if (claims == null) {
            throw new AccessDeniedException(
                "No security claims found — ensure SecurityFilter is registered");
        }

        @SuppressWarnings("unchecked")
        List<String> permissions = claims.get("permissions", List.class);

        if (permissions == null || !permissions.contains(requiredPermission.value())) {
            throw new AccessDeniedException(
                "Access denied — missing permission: " + requiredPermission.value());
        }

        return pjp.proceed();
    }

    private Claims extractClaims() {
        ServletRequestAttributes attrs =
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) return null;
        HttpServletRequest request = attrs.getRequest();
        return (Claims) request.getAttribute("claims");
    }
}
