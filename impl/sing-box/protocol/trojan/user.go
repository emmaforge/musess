package trojan

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.TrojanUser) error {
	h.users = users
	return h.service.UpdateUsers(common.MapIndexed(h.users, func(index int, it option.TrojanUser) int {
		return index
	}), common.Map(h.users, func(it option.TrojanUser) string {
		return it.Password
	}))
}
