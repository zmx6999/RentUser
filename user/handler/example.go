package handler

import (
	"context"

		example "190326/user/proto/example"
	"190326/models"
	"190326/utils"
	"github.com/afocus/captcha"
	"image/color"
	"github.com/garyburd/redigo/redis"
	"errors"
	"math/rand"
	"github.com/SubmailDem/submail"
		"strconv"
	"crypto/ecdsa"
	"crypto/elliptic"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"path"
)

type Example struct{}

// Call is a single request handler called via client.Call or the generated client code
func (e *Example) GenerateId(ctx context.Context, req *example.GenerateIdRequest, rsp *example.GenerateIdResponse) error {
	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	data, err := ccs.ChaincodeQuery(utils.ChaincodeId, "generateUserId", [][]byte{})
	if err != nil {
		return err
	}
	rsp.UserId = string(data)

	return nil
}

func (e *Example) Captcha(ctx context.Context, req *example.CaptchaRequest, rsp *example.CaptchaResponse) error {
	cpt := captcha.New()
	err := cpt.SetFont("comic.ttf")
	if err != nil {
		return err
	}
	cpt.SetSize(90, 40)
	cpt.SetDisturbance(captcha.MEDIUM)
	cpt.SetFrontColor(color.RGBA{255, 255, 255, 255})
	cpt.SetBkgColor(color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}, color.RGBA{0, 153, 0, 255})

	img, str := cpt.Create(4, captcha.NUM)

	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	_, err = cnn.Do("set", "captcha" + req.UserId, str, "EX", 3600)
	if err != nil {
		return err
	}

	rsp.Pix = img.Pix
	rsp.Stride = int64(img.Stride)
	rsp.Min = &example.CaptchaResponse_Point{X: int64(img.Rect.Min.X), Y: int64(img.Rect.Min.Y)}
	rsp.Max = &example.CaptchaResponse_Point{X: int64(img.Rect.Max.X), Y: int64(img.Rect.Max.Y)}

	return nil
}

func (e *Example) SmsCaptcha(ctx context.Context, req *example.SmsCaptchaRequest, rsp *example.SmsCaptchaResponse) error {
	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	str, err := redis.String(cnn.Do("get", "captcha" + req.UserId))
	if str == "" || req.Captcha != str {
		return errors.New("invalid captcha")
	}

	code := rand.Intn(8999) + 1001

	_, err = cnn.Do("set", "sms" + req.Mobile, strconv.Itoa(code), "EX", 3600)
	if err != nil {
		return err
	}

	messageconfig := make(map[string]string)
	messageconfig["appid"] = utils.MessageAppId
	messageconfig["appkey"] = utils.MessageAppKey
	messageconfig["signtype"] = "md5"

	messagexsend := submail.CreateMessageXSend()
	submail.MessageXSendAddTo(messagexsend, req.Mobile)
	submail.MessageXSendSetProject(messagexsend, utils.MessageProject)
	submail.MessageXSendAddVar(messagexsend, "code", strconv.Itoa(code))
	submail.MessageXSendRun(submail.MessageXSendBuildRequest(messagexsend), messageconfig)

	cnn.Do("del", "captcha" + req.UserId)

	return nil
}

func (e *Example) Register(ctx context.Context, req *example.RegisterRequest, rsp *example.RegisterResponse) error {
	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	str, err := redis.String(cnn.Do("get", "sms" + req.Mobile))
	if str == "" || req.SmsCaptcha != str {
		return errors.New("invalid sms captcha")
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return err
	}

	privateKeyHex, err := utils.EncodePrivateKey(privateKey)
	if err != nil {
		return err
	}

	rawPublicKey := privateKey.PublicKey
	publicKey := append(rawPublicKey.X.Bytes(), rawPublicKey.Y.Bytes()...)
	publicKeyHex := hex.EncodeToString(publicKey)

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "register", [][]byte{[]byte(req.UserId), []byte(req.Mobile), []byte(publicKeyHex)})
	if err != nil {
		return err
	}

	rsp.UserId = req.UserId
	rsp.Mobile = req.Mobile
	rsp.PublicKey = publicKeyHex
	rsp.PrivateKey = privateKeyHex

	cnn.Do("del", "sms" + req.Mobile)

	return nil
}

func (e *Example) AddNewKey(ctx context.Context, req *example.AddNewKeyRequest, rsp *example.AddNewKeyResponse) error {
	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	str, err := redis.String(cnn.Do("get", "sms" + req.Mobile))
	if str == "" || req.SmsCaptcha != str {
		return errors.New("invalid sms captcha")
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return err
	}

	privateKeyHex, err := utils.EncodePrivateKey(privateKey)
	if err != nil {
		return err
	}

	rawPublicKey := privateKey.PublicKey
	publicKey := append(rawPublicKey.X.Bytes(), rawPublicKey.Y.Bytes()...)
	publicKeyHex := hex.EncodeToString(publicKey)

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "addNewKey", [][]byte{[]byte(req.Mobile), []byte(publicKeyHex)})
	if err != nil {
		return err
	}

	rsp.Mobile = req.Mobile
	rsp.PublicKey = publicKeyHex
	rsp.PrivateKey = privateKeyHex

	cnn.Do("del", "sms" + req.Mobile)

	return nil
}

func (e *Example) Login(ctx context.Context, req *example.LoginRequest, rsp *example.LoginResponse) error {
	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	nonceStr := utils.GenerateNonceStr(41)
	sessionId := utils.GetSha256Str(req.Mobile + nonceStr)
	_, err = cnn.Do("set", sessionId, req.Mobile, "EX", 3600)
	if err != nil {
		return err
	}

	rsp.SessionId = sessionId

	return nil
}

func (e *Example) Logout(ctx context.Context, req *example.LogoutRequest, rsp *example.LogoutResponse) error {
	cnn, err := redis.Dial("tcp", utils.RedisHost + ":" + utils.RedisPort, redis.DialPassword(utils.RedisPassword))
	if err != nil {
		return err
	}
	defer cnn.Close()

	_, err = cnn.Do("del", req.SessionId)
	if err != nil {
		return err
	}

	return nil
}

func (e *Example) GetInfo(ctx context.Context, req *example.GetInfoRequest, rsp *example.GetInfoResponse) error {
	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	data, err := ccs.ChaincodeQuery(utils.ChaincodeId, "getUserInfo", [][]byte{[]byte(mobile)})
	if err != nil {
		return err
	}
	rsp.Data = data

	return nil
}

func (e *Example) Avatar(ctx context.Context, req *example.AvatarRequest, rsp *example.AvatarResponse) error {
	if len(req.Data) != int(req.FileSize) {
		return errors.New("file transfer error")
	}

	ext := path.Ext(req.FileName)
	fileId, err := utils.UploadFile(req.Data, ext[1:])
	if err != nil {
		return err
	}

	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "avatar", [][]byte{[]byte(mobile), []byte(fileId)})
	if err != nil {
		return err
	}

	return nil
}

func (e *Example) Rename(ctx context.Context, req *example.RenameRequest, rsp *example.RenameResponse) error {
	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "rename", [][]byte{[]byte(mobile), []byte(req.NewName)})
	if err != nil {
		return err
	}

	return nil
}

func (e *Example) Auth(ctx context.Context, req *example.AuthRequest, rsp *example.AuthResponse) error {
	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "auth", [][]byte{[]byte(mobile), []byte(req.RealName), []byte(req.IdCard)})
	if err != nil {
		return err
	}

	return nil
}

func (e *Example) GetKeys(ctx context.Context, req *example.GetKeysRequest, rsp *example.GetKeysResponse) error {
	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	data, err := ccs.ChaincodeQuery(utils.ChaincodeId, "getUserPublicKeys", [][]byte{[]byte(mobile)})
	if err != nil {
		return err
	}
	rsp.Data = data

	return nil
}

func (e *Example) DelKey(ctx context.Context, req *example.DelKeyRequest, rsp *example.DelKeyResponse) error {
	mobile, err := utils.GetMobile(req.SessionId)
	if err != nil {
		return err
	}

	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return err
	}

	_, err = ccs.ChaincodeUpdate(utils.ChaincodeId, "deleteKey", [][]byte{[]byte(mobile), []byte(req.PublicKey)})
	if err != nil {
		return err
	}

	return nil
}
