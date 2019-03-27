package main

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"errors"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/protos/peer"
	"math/rand"
)

const (
	UserObjectType = "User"

	FastDFSHost = "45.63.94.102"
	FastDFSPort = "8888"
)

func checkArgsNum(args []string, n int) error {
	if len(args) < n {
		return errors.New(fmt.Sprintf("%d argument(s) required", n))
	}

	return nil
}

func get(stub shim.ChaincodeStubInterface, objectType string, id string) ([]byte, error) {
	key, err := stub.CreateCompositeKey(objectType, []string{id})
	if err != nil {
		return nil, err
	}

	data, err := stub.GetState(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New(objectType+" "+id+" doesn't exist")
	}

	return data, nil
}

func recordExist(stub shim.ChaincodeStubInterface, objectType string, id string) (bool, error) {
	key, err := stub.CreateCompositeKey(objectType, []string{id})
	if err != nil {
		return false, err
	}

	data, err := stub.GetState(key)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}

	return true, nil
}

func add(stub shim.ChaincodeStubInterface, objectType string, id string, obj interface{}) error {
	exist, err := recordExist(stub, objectType, id)
	if err != nil {
		return err
	}
	if exist {
		return errors.New(objectType+" "+id+" already exists")
	}

	key, err := stub.CreateCompositeKey(objectType, []string{id})
	if err != nil {
		return err
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	err = stub.PutState(key, data)
	if err != nil {
		return err
	}

	return nil
}

func set(stub shim.ChaincodeStubInterface, objectType string, id string, obj interface{}) error {
	exist, err := recordExist(stub, objectType, id)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New(objectType+" "+id+" doesn't exist")
	}

	key, err := stub.CreateCompositeKey(objectType, []string{id})
	if err != nil {
		return err
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	err = stub.PutState(key, data)
	if err != nil {
		return err
	}

	return nil
}

func del(stub shim.ChaincodeStubInterface, objectType string, id string) error {
	exist, err := recordExist(stub, objectType, id)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New(objectType+" "+id+" doesn't exist")
	}

	key, err := stub.CreateCompositeKey(objectType, []string{id})
	if err != nil {
		return err
	}

	err = stub.DelState(key)
	if err != nil {
		return err
	}

	return nil
}

func generateId(stub shim.ChaincodeStubInterface, objectType string, length int) (string, error) {
	a := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}
	id := ""
	for i := 0; i < length; i++ {
		if i > 0 {
			id += a[rand.Intn(len(a))]
		} else {
			id += a[rand.Intn(len(a) - 1)]
		}
	}

	exist, err := recordExist(stub, objectType, id)
	if err != nil {
		return "", err
	}
	if exist {
		return generateId(stub, objectType, length)
	}

	return id, nil
}

func getQueryResult(stub shim.ChaincodeStubInterface, query map[string]interface{}) (shim.StateQueryIteratorInterface, error) {
	queryJson, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	queryStr := string(queryJson)
	return stub.GetQueryResult(queryStr)
}

func addDomainToUrl(url string) string {
	if url == "" {
		return ""
	}
	return "http://" + FastDFSHost + ":" + FastDFSPort + "/" + url
}

type User struct {
	ObjectType string
	UserId string
	Name string
	Mobile string
	RealName string
	IdCard string
	AvatarUrl string
	PublicKeys []string
}

func getUserByMobile(stub shim.ChaincodeStubInterface, mobile string) (*User, error) {
	query := map[string]interface{}{
		"selector": map[string]interface{}{
			"ObjectType": UserObjectType,
			"Mobile": mobile,
		},
	}

	iter, err := getQueryResult(stub, query)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var user User
	for iter.HasNext() {
		item, err := iter.Next()
		if err != nil {
			continue
		}

		err = json.Unmarshal(item.Value, &user)
		if user.UserId != "" {
			return &user, nil
		}
	}

	return nil, errors.New("USER NOT FOUND")
}

func userMobileExist(stub shim.ChaincodeStubInterface, mobile string) (bool, error) {
	query := map[string]interface{}{
		"selector": map[string]interface{}{
			"ObjectType": UserObjectType,
			"Mobile": mobile,
		},
		"use_index": []string{"_design/userDoc", "user"},
	}

	iter, err := getQueryResult(stub, query)
	if err != nil {
		return false, err
	}
	defer iter.Close()

	var user User
	for iter.HasNext() {
		item, err := iter.Next()
		if err != nil {
			continue
		}

		err = json.Unmarshal(item.Value, &user)
		if user.UserId != "" {
			return true, nil
		}
	}

	return false, nil
}

func setUserInfo(stub shim.ChaincodeStubInterface, mobile string, setUser func(*User) error) error {
	user, err := getUserByMobile(stub, mobile)
	if err != nil {
		return err
	}

	err = setUser(user)
	if err != nil {
		return err
	}

	return set(stub, UserObjectType, user.UserId, user)
}

type UserChaincode struct {

}

func generateUserId(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	id, err := generateId(stub, UserObjectType, 11)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte(id))
}

func register(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 3)
	if err != nil {
		return shim.Error(err.Error())
	}

	exist, err := userMobileExist(stub, args[1])
	if err != nil {
		return shim.Error(err.Error())
	}
	if exist {
		return shim.Error("mobile already exists")
	}

	var user User
	user.ObjectType = UserObjectType
	user.UserId = args[0]
	user.Mobile = args[1]
	user.Name = user.Mobile
	user.PublicKeys = append(user.PublicKeys, args[2])

	err = add(stub, UserObjectType, user.UserId, &user)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func addNewKey(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 2)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		user.PublicKeys = append(user.PublicKeys, args[1])
		return nil
	})

	return shim.Success(nil)
}

func getUserPublicKeys(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 1)
	if err != nil {
		return shim.Error(err.Error())
	}

	user, err := getUserByMobile(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	data, err := json.Marshal(user.PublicKeys)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(data)
}

func getUserInfo(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 1)
	if err != nil {
		return shim.Error(err.Error())
	}

	user, err := getUserByMobile(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	_data := make(map[string]interface{})
	_data["user_id"] = user.UserId
	_data["name"] = user.Name
	_data["mobile"] = user.Mobile
	_data["real_name"] = user.RealName
	_data["id_card"] = user.IdCard
	_data["avatar_url"] = addDomainToUrl(user.AvatarUrl)

	data, err := json.Marshal(_data)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(data)
}

func avatar(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 2)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		user.AvatarUrl = args[1]
		return nil
	})

	return shim.Success(nil)
}

func rename(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 2)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		user.Name = args[1]
		return nil
	})

	return shim.Success(nil)
}

func auth(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 3)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		user.RealName = args[1]
		user.IdCard = args[2]
		return nil
	})

	return shim.Success(nil)
}

func deleteKey(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 2)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		if len(user.PublicKeys) < 2 {
			return errors.New("CANNOT DELETE THE ONLY KEY")
		}

		var publicKeys []string
		for _, publicKey := range user.PublicKeys{
			if publicKey != args[1] {
				publicKeys = append(publicKeys, publicKey)
			}
		}
		user.PublicKeys = publicKeys

		return nil
	})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func deleteUser(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 1)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = del(stub, UserObjectType, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func changeMobile(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	err := checkArgsNum(args, 2)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = setUserInfo(stub, args[0], func(user *User) error {
		user.Mobile = args[1]
		return nil
	})
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (this *UserChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (this *UserChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "generateUserId":
		return generateUserId(stub, args)
	case "register":
		return register(stub, args)
	case "addNewKey":
		return addNewKey(stub, args)
	case "getUserInfo":
		return getUserInfo(stub, args)
	case "getUserPublicKeys":
		return getUserPublicKeys(stub, args)
	case "avatar":
		return avatar(stub, args)
	case "rename":
		return rename(stub, args)
	case "auth":
		return auth(stub, args)
	case "deleteKey":
		return deleteKey(stub, args)
	case "deleteUser":
		return deleteUser(stub, args)
	case "changeMobile":
		return changeMobile(stub, args)
	default:
		return shim.Error("method not found")
	}
}

func main()  {
	shim.Start(new(UserChaincode))
}
