package shadowsocks

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *MultiInbound) UpdateUsersByOptions(users []option.ShadowsocksUser) error {
	h.users = users
	return h.service.UpdateUsersWithPasswords(common.MapIndexed(h.users, func(index int, user option.ShadowsocksUser) int {
		return index
	}), common.Map(h.users, func(user option.ShadowsocksUser) string {
		return user.Password
	}))
}
