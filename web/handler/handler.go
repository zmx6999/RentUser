package handler

/*
39526876799
4b8ab9bf8edfa4f88087062463717c0a16c68c12d3adf6907e1dc11cc500790e86862147686bcbfbaaa3bd3bbe445bcf6aa6c4011ed464e4547f15bd6304d07a
2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d32353600000121024b8ab9bf8edfa4f88087062463717c0a16c68c12d3adf6907e1dc11cc500790e01210286862147686bcbfbaaa3bd3bbe445bcf6aa6c4011ed464e4547f15bd6304d07a0001210236870f572c6c275016764769196d5fb3d7577bcaacd0b8038175870b7a2e76cc00
3946aba1881d46d5f9d8fdce0671de12f88f1f1e16c6ee34ce85d35f5d93a9a74ae511704ad025b04bfd6675ffc1bcffc326a3f7d004f1e6a5bf03466505670e
2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d32353600000121023946aba1881d46d5f9d8fdce0671de12f88f1f1e16c6ee34ce85d35f5d93a9a70121024ae511704ad025b04bfd6675ffc1bcffc326a3f7d004f1e6a5bf03466505670e000121022cea2de226e4f9ae070ca42ba151d0cd588ecb7c8ab8609446f9cd565d56440e00
 */

import (
		"encoding/json"
	"net/http"
		"190326/utils"
	"github.com/julienschmidt/httprouter"
		USER "190326/user/proto/example"
		"context"
	"github.com/afocus/captcha"
	"image"
	"image/png"
	"github.com/zmx6999/FormValidation/FormValidation"
	"190326/models"
	"crypto/ecdsa"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"math/big"
	"crypto/elliptic"
	"errors"
	"github.com/micro/go-grpc"
)

func handleResponse(w http.ResponseWriter, code int, msg string, data interface{})  {
	w.Header().Set("content-type", "application/json")
	// we want to augment the response
	response := map[string]interface{}{
		"code": code,
		"msg": msg,
		"data": data,
	}

	// encode and write the response as json
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func success(w http.ResponseWriter, data interface{})  {
	handleResponse(w, 200, "ok", data)
}

func handleError(w http.ResponseWriter, code int, err error)  {
	handleResponse(w, code, err.Error(), nil)
}

func handleServiceError(w http.ResponseWriter, err error)  {
	errData := make(map[string]interface{})
	json.Unmarshal([]byte(err.Error()), &errData)
	code := int(utils.GetFloatValue(errData, "code", 0))
	msg := utils.GetStringValue(errData, "detail", "")
	handleResponse(w, code, msg, nil)
}

func getUserPublicKeys(mobile string) ([]string, error) {
	ccs, err := models.Initialize(utils.ChannelId, utils.UserName, utils.OrgName, utils.ChaincodeId, utils.ConfigFile)
	if err != nil {
		return nil, err
	}

	data, err := ccs.ChaincodeQuery(utils.ChaincodeId, "getUserPublicKeys", [][]byte{[]byte(mobile)})
	if err != nil {
		return nil, err
	}

	var publicKeyList []string
	json.Unmarshal(data, &publicKeyList)

	return publicKeyList, nil
}

func validateUser(mobile string, privateKeyHex string) (bool, error) {
	privateKey, err := utils.DecodePrivateKey(privateKeyHex)
	if err != nil {
		return false, err
	}

	nonceStr := utils.GenerateNonceStr(41)
	r, s, err := ecdsa.Sign(crypto_rand.Reader, privateKey, []byte(nonceStr))
	if err != nil {
		return false, err
	}

	publicKeyList, err := getUserPublicKeys(mobile)
	if err != nil {
		return false, err
	}

	for _, publicKeyHex := range publicKeyList{
		publicKey, err := hex.DecodeString(publicKeyHex)
		if err != nil {
			continue
		}

		var x, y big.Int
		x.SetBytes(publicKey[:len(publicKey) / 2])
		y.SetBytes(publicKey[len(publicKey) / 2:])

		rawPublicKey := ecdsa.PublicKey{elliptic.P256(), &x, &y}
		if ecdsa.Verify(&rawPublicKey, []byte(nonceStr), r, s) {
			return true, nil
		}
	}

	return false, nil
}

func GenerateUserId(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.GenerateId(context.TODO(), &USER.GenerateIdRequest{

	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	data := make(map[string]interface{})
	data["user_id"] = rsp.UserId
	success(w, data)
}

func Captcha(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.Captcha(context.TODO(), &USER.CaptchaRequest{
		UserId: p.ByName("user_id"),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	img := captcha.Image{&image.RGBA{Pix: rsp.Pix, Stride: int(rsp.Stride), Rect: image.Rect(int(rsp.Min.X), int(rsp.Min.Y), int(rsp.Max.X), int(rsp.Max.Y))}}

	if err := png.Encode(w, img); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func SmsCaptcha(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	request := make(map[string]interface{})
	request["user_id"] = utils.GetParam("user_id", r)
	request["mobile"] = utils.GetParam("mobile", r)
	request["captcha"] = utils.GetParam("captcha", r)

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "user_id",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "user_id cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "mobile",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "mobile cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:"mobile",
			ValidMethodName:"ChineseMobile",
			ValidMethodArgs:[]interface{}{},
			ErrMsg:"invalid mobile",
			Trim:true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "captcha",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "captcha cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err := gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.SmsCaptcha(context.TODO(), &USER.SmsCaptchaRequest{
		UserId: request["user_id"].(string),
		Mobile: request["mobile"].(string),
		Captcha: request["captcha"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	success(w, nil)
}

func Register(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "user_id",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "user_id cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "mobile",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "mobile cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:"mobile",
			ValidMethodName:"ChineseMobile",
			ValidMethodArgs:[]interface{}{},
			ErrMsg:"invalid mobile",
			Trim:true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "sms_captcha",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "sms_captcha cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err := gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.Register(context.TODO(), &USER.RegisterRequest{
		UserId: request["user_id"].(string),
		Mobile: request["mobile"].(string),
		SmsCaptcha: request["sms_captcha"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	data := make(map[string]interface{})
	data["user_id"] = rsp.UserId
	data["mobile"] = rsp.Mobile
	data["public_key"] = rsp.PublicKey
	data["private_key"] = rsp.PrivateKey

	success(w, data)
}

func AddNewKey(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "mobile",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "mobile cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:"mobile",
			ValidMethodName:"ChineseMobile",
			ValidMethodArgs:[]interface{}{},
			ErrMsg:"invalid mobile",
			Trim:true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "sms_captcha",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "sms_captcha cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err := gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.AddNewKey(context.TODO(), &USER.AddNewKeyRequest{
		Mobile: request["mobile"].(string),
		SmsCaptcha: request["sms_captcha"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	data := make(map[string]interface{})
	data["mobile"] = rsp.Mobile
	data["public_key"] = rsp.PublicKey
	data["private_key"] = rsp.PrivateKey

	success(w, data)
}

func Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "mobile",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "mobile cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:"mobile",
			ValidMethodName:"ChineseMobile",
			ValidMethodArgs:[]interface{}{},
			ErrMsg:"invalid mobile",
			Trim:true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "private_key",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "private_key cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err := gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	valid, err := validateUser(request["mobile"].(string), request["private_key"].(string))
	if err != nil {
		handleError(w, 4102, err)
		return
	}
	if !valid {
		handleError(w, 4103, errors.New("invalid private key"))
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.Login(context.TODO(), &USER.LoginRequest{
		Mobile: request["mobile"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "session_id", Path: "/", Value: rsp.SessionId, MaxAge: 3600})

	success(w, nil)
}

func Logout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.Logout(context.TODO(), &USER.LogoutRequest{
		SessionId: sessionId.Value,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "session_id", Path: "/", Value: "", MaxAge: -1})

	success(w, nil)
}

func GetUserInfo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.GetInfo(context.TODO(), &USER.GetInfoRequest{
		SessionId: sessionId.Value,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	data := make(map[string]interface{})
	json.Unmarshal(rsp.Data, &data)

	success(w, data)
}

func Avatar(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	data, head, err := utils.PrepareUploadFile(r, "avatar", []string{"jpg", "png", "jpeg"}, 1024 * 1024 * 2)
	if err != nil || sessionId.Value == "" {
		handleError(w, 4105, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.Avatar(context.TODO(), &USER.AvatarRequest{
		SessionId: sessionId.Value,
		Data: data,
		FileName: head.Filename,
		FileSize: head.Size,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	success(w, nil)
}

func Rename(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "new_name",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "new_name cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err = gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.Rename(context.TODO(), &USER.RenameRequest{
		SessionId: sessionId.Value,
		NewName: request["new_name"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	success(w, nil)
}

func Auth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "real_name",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "real_name cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:       "id_card",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "id_card cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
		&FormValidation.FieldValidation{
			FieldName:"id_card",
			ValidMethodName:"ChineseIdCard",
			ValidMethodArgs:[]interface{}{},
			ErrMsg:"invalid ID card",
			Trim:true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err = gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.Auth(context.TODO(), &USER.AuthRequest{
		SessionId: sessionId.Value,
		RealName: request["real_name"].(string),
		IdCard: request["id_card"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	success(w, nil)
}

func GetUserPublicKeys(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	rsp, err := exampleClient.GetKeys(context.TODO(), &USER.GetKeysRequest{
		SessionId: sessionId.Value,
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	var data []string
	json.Unmarshal(rsp.Data, &data)

	success(w, data)
}

func DeleteUserPublicKey(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	sessionId, err := r.Cookie("session_id")
	if err != nil || sessionId.Value == "" {
		handleError(w, 4104, errors.New("please login"))
		return
	}

	// decode the incoming request as json
	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fvs := []*FormValidation.FieldValidation{
		&FormValidation.FieldValidation{
			FieldName:       "public_key",
			ValidMethodName: "Require",
			ValidMethodArgs: []interface{}{},
			ErrMsg:          "public_key cannot be empty",
			Trim:            true,
			ValidEmpty:      true,
		},
	}

	gv := &FormValidation.GroupValidation{
		request,
		fvs,
	}
	_, err = gv.Validate()
	if err != nil {
		handleError(w, 4101, err)
		return
	}

	service := grpc.NewService()
	service.Init()
	// call the backend service
	exampleClient := USER.NewExampleService("go.micro.srv.user", service.Client())
	_, err = exampleClient.DelKey(context.TODO(), &USER.DelKeyRequest{
		SessionId: sessionId.Value,
		PublicKey: request["public_key"].(string),
	})
	if err != nil {
		handleServiceError(w, err)
		return
	}

	success(w, nil)
}
