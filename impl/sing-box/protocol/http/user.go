package http

import (
	"github.com/sagernet/sing/common/auth"
)

func (h *Inbound) UpdateUsers(users []auth.User) error {
	h.authenticator = auth.NewAuthenticator(users)
	return nil
}
