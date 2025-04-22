package router

import (
	"classnewsletter/controller"

	"github.com/gin-gonic/gin"
)

func Start() {
	e := gin.Default()
	e.LoadHTMLGlob("templates/*")   //加载html资源
	e.Static("/assets", "./assets") //加载网站格式图片视频资源
	e.GET("/register", controller.GORegister)
	e.POST("/register", controller.RegisterUser)         //注册
	e.GET("/login", controller.GoLogin)                  //登录
	e.GET("/captcha", controller.GenerateCaptchaHandler) //加载验证码
	e.POST("/login", controller.Login)
	e.GET("/PersonalInformation", controller.GoPersonalInformation) //个人信息
	e.GET("/exit", controller.GoLogout)                             //退出登录
	e.GET("/update", controller.GoUpdate)                           //更新个人信息
	e.POST("/update", controller.Update)
	e.GET("/inquire", controller.GoClassAllUser)                   //获取班级用户表
	e.POST("/inquire/by-studentid", controller.InquireStudentid)   //获取用户本班级的指定学号用户信息
	e.POST("/inquire/by-username", controller.InquireClassAndName) //获取用户本班级的指定名字用户信息
	e.POST("/delete-account", controller.CancelAnAccount)          //用户注销账号
	e.GET("/admin/login", controller.GoAdministratorLogin)         //管理员登录
	e.POST("/admin/login", controller.AdministratorLogin)
	e.GET("/administrator", controller.GOAdministrator)    //管理员查看用户信息
	e.GET("/admin/logout", controller.AdministratorLogout) //管理员退出
	e.GET("/admin/add-user", controller.GoAddUsers)        //添加用户
	e.POST("/admin/add-users", controller.AddUsers)
	e.POST("/admin/search/studentid", controller.AdministratorStudentid)  //管理员学号查询
	e.POST("/admin/search/class", controller.AdministratorClassAllUser)   //管理员班级查询
	e.POST("/admin/search/username", controller.AdministratorNameAllUser) //管理员名字查询
	e.GET("/admin/edit", controller.GoAdministratorUpdate)                //管理员更新用户信息
	e.POST("/admin/update-user", controller.AdministratorUpdate)
	e.POST("/admin/delete", controller.AdministratorDelete) //管理员删除用户
	// Excel导入导出相关路由
	e.GET("/admin/import-excel", controller.GoImportExcel)              //加载Excel导入页面
	e.POST("/admin/import-excel", controller.ImportExcel)               //处理Excel导入
	e.GET("/admin/export-excel", controller.ExportExcel)                //导出用户数据到Excel
	e.GET("/admin/download-template", controller.DownloadExcelTemplate) //下载Excel导入模板

	e.Run(":8080") //启动端口号
}
