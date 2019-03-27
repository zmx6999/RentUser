package main

import (
        "github.com/micro/go-log"
	        "github.com/micro/go-web"
                "190326/utils"
        "github.com/julienschmidt/httprouter"
        "190326/web/handler"
)

func main() {
	// create new web service
        service := web.NewService(
                web.Name("go.micro.web.web"),
                web.Version("latest"),
                web.Address(":" + utils.AppPort),
        )

	// initialise service
        if err := service.Init(); err != nil {
                log.Fatal(err)
        }

        r := httprouter.New()

        r.GET("/user/id", handler.GenerateUserId)
        r.GET("/user/captcha/:user_id", handler.Captcha)
        r.GET("/user/sms", handler.SmsCaptcha)
        r.POST("/user/register", handler.Register)
        r.POST("/user/newkey", handler.AddNewKey)
        r.POST("/user/login", handler.Login)
        r.GET("/user/logout", handler.Logout)
        r.GET("/user/info", handler.GetUserInfo)
        r.POST("/user/avatar", handler.Avatar)
        r.POST("/user/rename", handler.Rename)
        r.POST("/user/auth", handler.Auth)
        r.GET("/user/key", handler.GetUserPublicKeys)
        r.POST("/user/delkey", handler.DeleteUserPublicKey)

	// register html handler
	service.Handle("/", r)

	// run service
        if err := service.Run(); err != nil {
                log.Fatal(err)
        }
}
