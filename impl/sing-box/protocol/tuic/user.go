package tuic

import (
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/exceptions"
)

func (h *Inbound) UpdateUsers(users []option.TUICUser) error {
	var userList []int
	var userNameList []string
	var userUUIDList [][16]byte
	var userPasswordList []string
	for index, user := range users {
		if user.UUID == "" {
			return exceptions.New("missing uuid for user ", index)
		}
		userUUID, err := uuid.FromString(user.UUID)
		if err != nil {
			return exceptions.Cause(err, "invalid uuid for user ", index)
		}
		userList = append(userList, index)
		userNameList = append(userNameList, user.Name)
		userUUIDList = append(userUUIDList, userUUID)
		userPasswordList = append(userPasswordList, user.Password)
	}
	h.server.UpdateUsers(userList, userUUIDList, userPasswordList)
	h.userNameList = userNameList
	return nil
}
