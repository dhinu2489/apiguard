package io.apiguard.rbac;

import java.lang.annotation.*;

/**
 * Declares the permission required to invoke a controller method.
 *
 * <pre>{@code
 * @DeleteMapping("/invoices/{id}")
 * @RequiresPermission("invoices:delete")
 * public ResponseEntity<Void> deleteInvoice(@PathVariable String id) { ... }
 * }</pre>
 *
 * Enforced at runtime by {@link RBACEnforcer}.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresPermission {
    /** The permission string, e.g. {@code "invoices:write"} */
    String value();
}
