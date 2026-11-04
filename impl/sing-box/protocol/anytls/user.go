package anytls

import (
	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.AnyTLSUser) error {
	h.service.UpdateUsers(common.Map(users, func(it option.AnyTLSUser) anytls.User {
		return (anytls.User)(it)
	}))
	return nil
}
