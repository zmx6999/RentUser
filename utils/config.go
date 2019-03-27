package utils

import (
	"github.com/astaxie/beego/config"
	"github.com/astaxie/beego"
	"os"
)

var (
	AppPort string

	ChannelId string
	UserName string
	OrgName string
	ChaincodeId string
	ConfigFile string

	RedisHost string
	RedisPort string
	RedisPassword string

	FastDFSClientConfigFile string

	MessageAppId string
	MessageAppKey string
	MessageProject string
)

func init()  {
	conf, err := config.NewConfig("ini", "/root/go/src/190326/conf/app.conf")
	if err != nil {
		beego.Error(err)
		os.Exit(-1)
	}

	AppPort = conf.String("AppPort")

	ChannelId = conf.String("ChannelId")
	UserName = conf.String("UserName")
	OrgName = conf.String("OrgName")
	ChaincodeId = conf.String("ChaincodeId")
	ConfigFile = conf.String("ConfigFile")

	RedisHost = conf.String("RedisHost")
	RedisPort = conf.String("RedisPort")
	RedisPassword = conf.String("RedisPassword")

	FastDFSClientConfigFile = conf.String("FastDFSClientConfigFile")

	MessageAppId = conf.String("MessageAppId")
	MessageAppKey = conf.String("MessageAppKey")
	MessageProject = conf.String("MessageProject")
}
