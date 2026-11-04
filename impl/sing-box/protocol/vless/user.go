package vless

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	h.users = users
	h.service.UpdateUsers(common.MapIndexed(h.users, func(index int, _ option.VLESSUser) int {
		return index
	}), common.Map(h.users, func(it option.VLESSUser) string {
		return it.UUID
	}), common.Map(h.users, func(it option.VLESSUser) string {
		return it.Flow
	}))
	return nil
}
