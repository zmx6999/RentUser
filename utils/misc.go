package utils

import (
	"net/http"
	"mime/multipart"
	"strings"
	"path"
	"errors"
	"github.com/weilaihui/fdfs_client"
	"crypto/ecdsa"
	"bytes"
	"encoding/gob"
	"crypto/elliptic"
	"encoding/hex"
	"math/rand"
	"crypto/sha256"
	"github.com/garyburd/redigo/redis"
)

func Find(a []string, x string) int {
	for i := 0; i < len(a); i++ {
		if a[i] == x {
			return i
		}
	}
	return -1
}

func PrepareUploadFile(r *http.Request, key string, allowedTypes []string, allowedMaxSize int64) ([]byte, *multipart.FileHeader, error) {
	file, head, err := r.FormFile(key)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	ext := strings.ToLower(path.Ext(head.Filename))
	if Find(allowedTypes, ext[1:]) < 0 {
		return nil, nil, errors.New("FILE TYPE SHOULD BE " + strings.Join(allowedTypes, ","))
	}
	if head.Size > allowedMaxSize {
		return nil, nil, errors.New("FILE SIZE EXCEED")
	}

	data := make([]byte, head.Size)
	_, err = file.Read(data)
	if err != nil {
		return nil, nil, err
	}

	return data, head, nil
}

func UploadFile(data []byte, ext string) (string, error) {
	client, err := fdfs_client.NewFdfsClient(FastDFSClientConfigFile)
	if err != nil {
		return "", err
	}

	r, err := client.UploadByBuffer(data, ext)
	if err != nil {
		return "", err
	}

	return r.RemoteFileId, nil
}

func GetStringValue(data map[string]interface{}, key string, defaultValue string) string {
	r, ok := data[key]
	if ok {
		return r.(string)
	}
	return defaultValue
}

func GetFloatValue(data map[string]interface{}, key string, defaultValue float64) float64 {
	r, ok := data[key]
	if ok {
		return r.(float64)
	}
	return defaultValue
}

func GetIntValue(data map[string]interface{}, key string, defaultValue int) int {
	r, ok := data[key]
	if ok {
		return r.(int)
	}
	return defaultValue
}

func GetParam(key string, r *http.Request) string {
	query := r.URL.Query()
	if query[key] != nil && len(query[key]) > 0 {
		return query[key][0]
	}
	return ""
}

func EncodePrivateKey(privateKey *ecdsa.PrivateKey) (string, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	gob.Register(elliptic.P256())
	err := encoder.Encode(privateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer.Bytes()), nil
}

func DecodePrivateKey(privateKeyHex string) (*ecdsa.PrivateKey, error) {
	data, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	decoder := gob.NewDecoder(bytes.NewBuffer(data))
	gob.Register(elliptic.P256())
	var privateKey ecdsa.PrivateKey
	err = decoder.Decode(&privateKey)
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}

func GenerateNonceStr(length int) string {
	x := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}
	str := ""
	for i := 0; i < length; i++ {
		str += x[rand.Intn(len(x))]
	}
	return str
}

func GetSha256Str(x string) string {
	h := sha256.New()
	h.Write([]byte(x))
	return hex.EncodeToString(h.Sum(nil))
}

func GetMobile(sessionId string) (string, error) {
	cnn, err := redis.Dial("tcp", RedisHost + ":" + RedisPort, redis.DialPassword(RedisPassword))
	if err != nil {
		return "", err
	}
	defer cnn.Close()

	return redis.String(cnn.Do("get", sessionId))
}
