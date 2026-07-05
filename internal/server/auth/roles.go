package auth

import "fmt"

// Role is a console role. Roles are strictly ordered:
// viewer < operator < admin (docs/console-ops.md §4).
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// roleRank orders roles for AtLeast. Unknown roles rank 0: below viewer,
// so a corrupted users file fails closed.
var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// AtLeast reports whether r grants at least min's privileges.
func (r Role) AtLeast(min Role) bool {
	return roleRank[r] >= roleRank[min] && roleRank[r] > 0
}

// ParseRole validates a role string from config, CLI, or API input.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if roleRank[r] == 0 {
		return "", fmt.Errorf("invalid role %q (viewer|operator|admin)", s)
	}
	return r, nil
}
