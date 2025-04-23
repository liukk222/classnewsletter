package controller

import (
	"classnewsletter/dao"
	"classnewsletter/model"
	"encoding/hex"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/mojocn/base64Captcha"
	"github.com/xuri/excelize/v2"
)

// 全局 securecookie 对象
var cookieHandler *securecookie.SecureCookie

func init() {
	// 读取这些密钥
	// 或使用 securecookie.GenerateRandomKey(32) 生成密钥并安全存储
	hashKey, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		log.Fatal("无法解码 hashKey:", err)
	}

	blockKey, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		log.Fatal("无法解码 blockKey:", err)
	}

	cookieHandler = securecookie.New(hashKey, blockKey)
}

func GORegister(c *gin.Context) { //加载注册页面
	c.HTML(200, "register.html", nil)
}

func RegisterUser(c *gin.Context) { //注册
	studentid := c.PostForm("studentid")
	class := c.PostForm("class")
	password := c.PostForm("password")
	password2 := c.PostForm("password2")
	if studentid != "" && password != "" && class != "" {
		if password == password2 {
			user := model.User{
				Studentid: studentid,
				Class:     class,
				Password:  password,
			}
			u := dao.Mgr.Login(studentid)
			fmt.Printf("u.Studentid: %v\n", u.Studentid)
			if u.Studentid == "" {
				dao.Mgr.Redirect(&user)
				c.Redirect(301, "/login")
			} else {
				c.HTML(200, "register.html", gin.H{
					"error": "学号重复",
				})
			}

		} else {
			c.HTML(200, "register.html", gin.H{
				"error": "密码不一致",
			})
		}
	} else {
		c.HTML(200, "register.html", gin.H{
			"error": "学号与密码以及班级不能为空",
		})
	}
}

// 存储验证码实例
var store = base64Captcha.DefaultMemStore
var customChars = "2345679abdefghjnrtyADEFGHJLNRTY"

// 生成验证码的处理函数
func GenerateCaptchaHandler(c *gin.Context) {
	// 使用自定义字符集配置
	driverConfig := base64Captcha.DriverString{
		Height:          80,
		Width:           240,
		NoiseCount:      0,
		ShowLineOptions: 2,
		Length:          4,
		Source:          customChars,
		BgColor: &color.RGBA{
			R: 255,
			G: 255,
			B: 255,
			A: 255,
		},
		Fonts: []string{"wqy-microhei.ttc"},
	}

	driver := driverConfig.ConvertFonts()
	captcha := base64Captcha.NewCaptcha(driver, store)
	id, b64s, _, err := captcha.Generate()

	if err != nil {
		c.JSON(500, gin.H{
			"code": 500,
			"msg":  "验证码生成失败",
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 200,
		"data": gin.H{
			"captchaId":  id,
			"captchaImg": b64s,
		},
	})
}

func GoLogin(c *gin.Context) { //加载登录页面
	c.HTML(200, "login.html", nil)
}

func Login(c *gin.Context) { //登录
	// 获取表单数据
	studentid := c.PostForm("studentid")
	password := c.PostForm("password")
	captchaId := c.PostForm("captchaId")
	captchaValue := c.PostForm("captcha")

	// 验证验证码
	if !store.Verify(captchaId, captchaValue, true) {
		c.HTML(200, "login.html", "验证码错误")
		return
	}

	// 验证用户
	u := dao.Mgr.Login(studentid)
	if u.Studentid == "" {
		c.HTML(200, "login.html", "用户名不存在！")
		return
	}

	if u.Password != password {
		c.HTML(200, "login.html", "密码错误")
		return
	}

	// 登录成功，创建加密的 cookie 数据
	userData := map[string]string{
		"userid": strconv.Itoa(int(u.ID)),
		// 可以添加更多需要存储的用户数据
	}

	// 对数据进行编码和加密
	encoded, err := cookieHandler.Encode("user-session", userData)
	if err != nil {
		log.Println("加密 Cookie 失败:", err)
		c.HTML(200, "login.html", "登录失败，请重试")
		return
	}

	// 设置加密的 cookie
	c.SetCookie(
		"user-session", // cookie 名称
		encoded,        // 加密后的值
		600*600,        // 最大生存时间（秒）
		"/",            // 路径
		"localhost",    // 域名
		false,          // 是否只通过 HTTPS 发送
		true,           // 是否禁止 JavaScript 访问
	)

	// 重定向到个人信息页面
	c.Redirect(301, "/PersonalInformation")
}

// 解析 Cookie 的辅助函数（在需要使用 Cookie 的其他处理函数中使用）
func GetUserFromCookie(c *gin.Context) (uint, error) {
	// 获取 cookie
	cookie, err := c.Cookie("user-session")
	if err != nil {
		return 0, err
	}

	// 解密 cookie
	userData := make(map[string]string)
	err = cookieHandler.Decode("user-session", cookie, &userData)
	if err != nil {
		return 0, err
	}

	// 获取用户 ID
	userIDStr, ok := userData["userid"]
	if !ok {
		return 0, err
	}

	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint(userID), nil
}

func GoPersonalInformation(c *gin.Context) { //加载个人信息
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "userbug.html", nil)

	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			c.HTML(200, "PersonalInformation.html", gin.H{
				"studentid":   user.Studentid,
				"class":       user.Class,
				"username":    user.Username,
				"password":    user.Password,
				"phonenumber": user.Phonenumber,
				"qqnumber":    user.Qqnumber,
				"wxnumber":    user.Wxnumber,
				"addres":      user.Address,
			})
		} else {
			c.HTML(200, "userbug.html", nil)

		}

	}

}

func GoLogout(c *gin.Context) { //退出
	//清除cookie
	c.SetCookie(
		"user-session", // name
		"",             // value (设为空)
		-1,             // maxAge (设为-1表示立即过期)
		"/",            // path (必须与设置时一致)
		"localhost",    // domain (必须与设置时一致)
		false,          // secure
		true,           // httpOnly
	)
	c.HTML(200, "login.html", nil)
}

func GoUpdate(c *gin.Context) { //加载更新个人信息
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "userbug.html", nil)
	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			c.HTML(200, "update.html", gin.H{
				"studentid":   user.Studentid,
				"class":       user.Class,
				"username":    user.Username,
				"password":    user.Password,
				"phonenumber": user.Phonenumber,
				"qqnumber":    user.Qqnumber,
				"wxnumber":    user.Wxnumber,
				"addres":      user.Address,
			})
		} else {
			c.HTML(200, "userbug.html", nil)

		}

	}
}

func Update(c *gin.Context) { //更新个人信息
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "login.html", "cookie错误，请重新登录")
		return
	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			class := c.PostForm("class")
			username := c.PostForm("username")
			password := c.PostForm("password")
			phonenumber := c.PostForm("phonenumber")
			qqnumber := c.PostForm("qqnumber")
			wxnumber := c.PostForm("wxnumber")
			addres := c.PostForm("addres")
			user.Class = class
			user.Username = username
			user.Password = password
			user.Phonenumber = phonenumber
			user.Qqnumber = qqnumber
			user.Wxnumber = wxnumber
			user.Address = addres
			dao.Mgr.UpdateUser(user)
			c.Redirect(301, "/PersonalInformation")
		} else {
			c.HTML(200, "userbug.html", nil)
		}
	}
}

func GoClassAllUser(c *gin.Context) { //获取班级用户表
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "login.html", "cookie错误，请重新登录")
		return
	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			users, error := dao.Mgr.GetClassAllUser(user.Class)
			if error != nil {
				c.HTML(200, "buginquire.html", nil)
			} else {
				c.HTML(200, "inquire.html", users)
			}
		} else {
			c.HTML(200, "userbug.html", nil)

		}
	}
}

func InquireStudentid(c *gin.Context) { //获取用户本班级的指定学号用户信息
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "userbug.html", nil)
	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			studentid := c.PostForm("studentid")
			u := dao.Mgr.GetStudentidAndClassUser(studentid, user.Class)
			if u.Studentid != "" {
				c.HTML(200, "InquireStudentid.html", gin.H{
					"studentid":   u.Studentid,
					"class":       u.Class,
					"username":    u.Username,
					"phonenumber": u.Phonenumber,
					"qqnumber":    u.Qqnumber,
					"wxnumber":    u.Wxnumber,
					"addres":      u.Address,
				})
			} else {
				c.HTML(200, "bugInquireStudentidClass.html", nil)
			}

		} else {
			c.HTML(200, "userbug.html", nil)
		}
	}
}

func InquireClassAndName(c *gin.Context) { //获取用户本班级的指定名字用户信息
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "userbug.html", nil)
	} else {

		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			name := c.PostForm("username")
			users, error := dao.Mgr.GetClassAndNanmeemAllUser(user.Class, name)
			if error != nil {
				c.HTML(200, "bugInquireStudentidClass.html", nil)
			} else {
				c.HTML(200, "inquire.html", users)
			}
		} else {
			c.HTML(200, "userbug.html", nil)
		}
	}
}

func CancelAnAccount(c *gin.Context) { //用户注销账号
	s, err := GetUserFromCookie(c)
	if err != nil {
		c.HTML(200, "userbug.html", nil)
	} else {
		user := dao.Mgr.GetIdUser(s)
		if user.Studentid != "" {
			studentids := c.Query("studentid")
			if studentids == user.Studentid {
				dao.Mgr.DeleteUser(user)
				//清除cookie
				c.SetCookie(
					"userid",    // name
					"",          // value (设为空)
					-1,          // maxAge (设为-1表示立即过期)
					"/",         // path (必须与设置时一致)
					"localhost", // domain (必须与设置时一致)
					false,       // secure
					true,        // httpOnly
				)
				c.Redirect(301, "/login")
			} else {
				c.SetCookie(
					"userid",    // name
					"",          // value (设为空)
					-1,          // maxAge (设为-1表示立即过期)
					"/",         // path (必须与设置时一致)
					"localhost", // domain (必须与设置时一致)
					false,       // secure
					true,        // httpOnly
				)
				c.Redirect(301, "/login")
				c.HTML(200, "norighttocancel.html", nil)
			}
		} else {
			c.HTML(200, "userbug.html", nil)
		}
	}
}
func GoAdministratorLogin(c *gin.Context) { //加载管理员登录
	c.HTML(200, "administratorlogin.html", nil)
}

func AdministratorLogin(c *gin.Context) { //管理员登录
	administrator := c.PostForm("administrator")
	password := c.PostForm("password")

	if administrator == "root" {
		if password == "123456" {
			// 创建管理员数据
			adminData := map[string]string{
				"role": "administrator",
				"id":   administrator,
			}

			// 使用 securecookie 加密数据
			encoded, err := cookieHandler.Encode("admin-session", adminData)
			if err != nil {
				log.Println("加密管理员 Cookie 失败:", err)
				c.HTML(200, "administratorlogin.html", "登录失败，请重试")
				return
			}

			// 设置加密的 cookie
			c.SetCookie(
				"admin-session", // 使用不同的名称区分管理员和普通用户
				encoded,         // 加密后的值
				600*600,         // 最大生存时间（秒）
				"/",             // 路径
				"localhost",     // 域名
				false,           // 是否只通过 HTTPS 发送
				true,            // 是否禁止 JavaScript 访问
			)

			c.Redirect(301, "/administrator")
		} else {
			c.HTML(200, "administratorlogin.html", "密码错误")
			return
		}
	} else {
		c.HTML(200, "administratorlogin.html", "账号错误")
		return
	}
}

// 添加一个辅助函数来验证管理员身份
func IsAdministrator(c *gin.Context) bool {
	// 获取 cookie
	cookie, err := c.Cookie("admin-session")
	if err != nil {
		return false
	}

	// 解密 cookie
	adminData := make(map[string]string)
	err = cookieHandler.Decode("admin-session", cookie, &adminData)
	if err != nil {
		return false
	}

	// 验证角色
	role, ok := adminData["role"]
	if !ok || role != "administrator" {
		return false
	}

	return true
}

func GOAdministrator(c *gin.Context) { //管理员查看用户信息

	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
	} else {
		users, error := dao.Mgr.GetAllUser()
		if error != nil {
			c.HTML(200, "administratorbug.html", nil)
		} else {
			c.HTML(200, "administrator.html", users)
		}
	}

	/*s, err := c.Cookie("administratorcookie")
	if err != nil {
		c.HTML(200, "administratorbug.html", nil)
	} else {
		if s == "administrator" {
			users, error := dao.Mgr.GetAllUser()
			if error != nil {
				c.HTML(200, "administratorbug.html", nil)
			} else {
				c.HTML(200, "administrator.html", users)
			}

		} else {
			c.HTML(200, "administratorbug.html", nil)
		}

	}*/

}

func AdministratorLogout(c *gin.Context) { //管理员退出
	c.SetCookie(
		"admin-session", // name
		"",              // value (设为空)
		-1,              // maxAge (设为-1表示立即过期)
		"/",             // path (必须与设置时一致)
		"localhost",     // domain (必须与设置时一致)
		false,           // secure
		true,            // httpOnly
	)
	c.HTML(200, "administratorlogin.html", nil)
}

func GoAddUsers(c *gin.Context) { //加载管理员添加用户
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		c.HTML(200, "addusers.html", nil)
	}

	/*s, err := c.Cookie("administratorcookie")
	if err != nil {
		c.HTML(200, "administratorbug.html", nil)
	} else {
		if s == "administrator" {
			c.HTML(200, "addusers.html", nil)
		} else {
			c.HTML(200, "administratorbug.html", nil)
		}

	}*/

}

func AddUsers(c *gin.Context) { //管理员添加用户
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		studentid := c.PostForm("studentid")
		class := c.PostForm("class")
		username := c.PostForm("username")
		password := c.PostForm("password")
		phonenumber := c.PostForm("phonenumber")
		qqnumber := c.PostForm("qqnumber")
		wxnumber := c.PostForm("wxnumber")
		addres := c.PostForm("addres")
		u := dao.Mgr.Login(studentid)
		if u.Studentid == "" {
			user := model.User{
				Studentid:   studentid,
				Class:       class,
				Username:    username,
				Password:    password,
				Phonenumber: phonenumber,
				Qqnumber:    qqnumber,
				Wxnumber:    wxnumber,
				Address:     addres,
			}
			dao.Mgr.Redirect(&user)
			c.Redirect(301, "/administrator")
		} else {
			c.HTML(200, "addusers.html", gin.H{
				"error": "学号重复",
			})
		}
	}

}

func AdministratorStudentid(c *gin.Context) { //管理员学号查询
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
		return
	} else {
		studentid := c.PostForm("studentid")
		user := dao.Mgr.Login(studentid)
		if user.Studentid != "" {
			c.HTML(200, "administratorstudentid.html", gin.H{
				"studentid":   user.Studentid,
				"class":       user.Class,
				"username":    user.Username,
				"password":    user.Password,
				"phonenumber": user.Phonenumber,
				"qqnumber":    user.Qqnumber,
				"wxnumber":    user.Wxnumber,
				"addres":      user.Address,
			})
		} else {
			c.HTML(200, "administratorstudentidbug.html", nil)
		}
	}
}

func AdministratorClassAllUser(c *gin.Context) { //管理员班级查询
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		class := c.PostForm("class")
		users, error := dao.Mgr.GetClassAllUser(class)
		if error != nil {
			c.HTML(200, "administratorstudentidbug.html", nil)
		} else {
			if len(users) == 0 {
				c.HTML(200, "administratorstudentidbug.html", nil)
			} else {
				c.HTML(200, "classname.html", users)
			}
		}

	}

}

func AdministratorNameAllUser(c *gin.Context) { //管理员名字查询
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		name := c.PostForm("username")
		users, error := dao.Mgr.GetNameAllUser(name)
		if error != nil {
			c.HTML(200, "administratorstudentidbug.html", nil)
		} else {
			if len(users) == 0 {
				c.HTML(200, "administratorstudentidbug.html", nil)
			} else {
				c.HTML(200, "classname.html", users)
			}

		}

	}

}

func GoAdministratorUpdate(c *gin.Context) { //加载管理员更新
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		studentid := c.Query("studentid")
		user := dao.Mgr.Login(studentid)
		if user.Studentid != "" {
			c.HTML(200, "administratorupdate.html", gin.H{
				"studentid":   user.Studentid,
				"class":       user.Class,
				"username":    user.Username,
				"password":    user.Password,
				"phonenumber": user.Phonenumber,
				"qqnumber":    user.Qqnumber,
				"wxnumber":    user.Wxnumber,
				"addres":      user.Address,
			})
		} else {
			c.HTML(200, "administratorstudentidbug.html", nil)
		}
	}

}

func AdministratorUpdate(c *gin.Context) { //管理员更新
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")

	} else {
		studentids := c.Query("studentid")
		user := dao.Mgr.Login(studentids)
		if user.Studentid != "" {
			studentid := c.PostForm("studentid")
			class := c.PostForm("class")
			username := c.PostForm("username")
			password := c.PostForm("password")
			phonenumber := c.PostForm("phonenumber")
			qqnumber := c.PostForm("qqnumber")
			wxnumber := c.PostForm("wxnumber")
			addres := c.PostForm("addres")
			user.Studentid = studentid
			user.Class = class
			user.Username = username
			user.Password = password
			user.Phonenumber = phonenumber
			user.Qqnumber = qqnumber
			user.Wxnumber = wxnumber
			user.Address = addres
			dao.Mgr.UpdateUser(&user)
			c.Redirect(301, "/administrator")
		} else {
			c.HTML(200, "administratorstudentidbug.html", nil)
		}

	}
}

func AdministratorDelete(c *gin.Context) { //管理员删除
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
		return
	} else {
		studentids := c.Query("studentid")
		user := dao.Mgr.Login(studentids)
		if user.Studentid != "" {
			dao.Mgr.DeleteUser(&user)
			c.Redirect(301, "/administrator")
		} else {
			c.HTML(200, "administratorstudentidbug.html", nil)
		}
	}
}

// GoImportExcel 加载Excel导入页面
func GoImportExcel(c *gin.Context) {
	// 检查是否是管理员
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
		return
	}

	c.HTML(200, "import_excel.html", nil)
}

// ImportExcel 处理Excel文件导入
func ImportExcel(c *gin.Context) {
	// 检查是否是管理员
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
		return
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("excel_file")
	if err != nil {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "上传文件失败: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// 检查文件扩展名
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".xlsx" && ext != ".xls" {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "只支持 .xlsx 或 .xls 格式的Excel文件",
		})
		return
	}

	// 创建临时文件保存上传的Excel
	tempFile, err := os.CreateTemp("", "upload-*.xlsx")
	if err != nil {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "创建临时文件失败: " + err.Error(),
		})
		return
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name()) // 处理完后删除临时文件

	// 将上传的文件保存到临时文件
	_, err = io.Copy(tempFile, file)
	if err != nil {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "保存文件失败: " + err.Error(),
		})
		return
	}

	// 打开Excel文件进行解析
	f, err := excelize.OpenFile(tempFile.Name())
	if err != nil {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "打开Excel文件失败: " + err.Error(),
		})
		return
	}
	defer f.Close()

	// 获取第一个工作表名
	sheetName := f.GetSheetName(0)

	// 获取工作表中的所有行
	rows, err := f.GetRows(sheetName)
	if err != nil {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "读取Excel数据失败: " + err.Error(),
		})
		return
	}

	// 检查数据是否为空
	if len(rows) <= 1 { // 只有标题行或没有数据
		c.HTML(200, "import_excel.html", gin.H{
			"error": "Excel文件中没有数据",
		})
		return
	}

	// 确定表头索引
	headerMap := make(map[string]int)
	headers := rows[0] // 第一行为表头

	// 映射必要的列
	requiredColumns := []string{"学号", "班级", "密码"}
	for i, header := range headers {
		headerMap[header] = i
	}

	// 检查是否包含必要的列
	missingColumns := []string{}
	for _, col := range requiredColumns {
		if _, exists := headerMap[col]; !exists {
			missingColumns = append(missingColumns, col)
		}
	}

	if len(missingColumns) > 0 {
		c.HTML(200, "import_excel.html", gin.H{
			"error": "Excel文件缺少必要的列: " + strings.Join(missingColumns, ", "),
		})
		return
	}

	// 统计信息
	success := 0
	duplicates := 0
	failures := 0
	var errorMessages []string

	// 从第二行开始（跳过表头）导入数据
	for i := 1; i < len(rows); i++ {
		row := rows[i]

		// 检查行是否有足够的列
		if len(row) < len(headers) {
			failures++
			errorMessages = append(errorMessages, fmt.Sprintf("第%d行: 列数不足", i+1))
			continue
		}

		// 获取必要字段
		studentid := row[headerMap["学号"]]
		class := row[headerMap["班级"]]
		password := row[headerMap["密码"]]

		// 检查必要字段是否为空
		if studentid == "" || class == "" || password == "" {
			failures++
			errorMessages = append(errorMessages, fmt.Sprintf("第%d行: 学号、班级或密码为空", i+1))
			continue
		}

		// 检查学号是否已存在
		existingUser := dao.Mgr.Login(studentid)
		if existingUser.Studentid != "" {
			duplicates++
			continue
		}

		// 创建用户对象
		user := model.User{
			Studentid: studentid,
			Class:     class,
			Password:  password,
		}

		// 可选字段
		if idx, exists := headerMap["姓名"]; exists && idx < len(row) {
			user.Username = row[idx]
		}
		if idx, exists := headerMap["电话号码"]; exists && idx < len(row) {
			user.Phonenumber = row[idx]
		}
		if idx, exists := headerMap["QQ号码"]; exists && idx < len(row) {
			user.Qqnumber = row[idx]
		}
		if idx, exists := headerMap["微信号"]; exists && idx < len(row) {
			user.Wxnumber = row[idx]
		}
		if idx, exists := headerMap["地址"]; exists && idx < len(row) {
			user.Address = row[idx]
		}

		// 保存到数据库
		dao.Mgr.Redirect(&user)
		success++
	}

	// 准备结果信息
	resultInfo := fmt.Sprintf("导入完成! 成功: %d, 重复(已跳过): %d, 失败: %d", success, duplicates, failures)

	// 显示结果
	c.HTML(200, "import_excel.html", gin.H{
		"success":       success > 0,
		"resultInfo":    resultInfo,
		"errorMessages": errorMessages,
	})
}

// ExportExcel 导出用户数据到Excel文件
func ExportExcel(c *gin.Context) {
	// 检查是否是管理员
	if !IsAdministrator(c) {
		// 非管理员，重定向到登录页面
		c.Redirect(301, "/admin/login")
		return
	}

	// 获取筛选条件（可选）
	class := c.Query("class")

	var users []model.User
	var err error

	// 根据条件获取用户
	if class != "" {
		// 如果提供了班级，只导出该班级的用户
		users, err = dao.Mgr.GetClassAllUser(class)
	} else {
		// 否则导出所有用户
		users, err = dao.Mgr.GetAllUser()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户数据失败"})
		return
	}

	// 创建新的Excel文件
	f := excelize.NewFile()
	defer f.Close()

	// 设置表头
	headers := []string{"学号", "班级", "姓名", "密码", "电话号码", "QQ号码", "微信号", "地址"}
	for colIndex, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(colIndex+1, 1)
		f.SetCellValue("Sheet1", cell, header)
	}

	// 填充数据
	for rowIndex, user := range users {
		rowData := []interface{}{
			user.Studentid,
			user.Class,
			user.Username,
			user.Password,
			user.Phonenumber,
			user.Qqnumber,
			user.Wxnumber,
			user.Address,
		}

		for colIndex, value := range rowData {
			cell, _ := excelize.CoordinatesToCellName(colIndex+1, rowIndex+2)
			f.SetCellValue("Sheet1", cell, value)
		}
	}

	// 调整列宽
	for i := range headers {
		colName, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth("Sheet1", colName, colName, 15)
	}

	// 设置文件名
	filename := "班级通讯录_"
	if class != "" {
		filename += class + "_"
	}
	filename += "导出.xlsx"

	// 设置响应头，作为下载文件返回
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Transfer-Encoding", "binary")

	// 将文件写入响应
	err = f.Write(c.Writer)
	if err != nil {
		log.Println("导出Excel文件失败:", err)
		c.Status(http.StatusInternalServerError)
		return
	}
}

// DownloadExcelTemplate 下载Excel导入模板
func DownloadExcelTemplate(c *gin.Context) {
	// 创建新的Excel文件作为模板
	f := excelize.NewFile()
	defer f.Close()

	// 设置表头（带标记必填字段）
	headers := []string{"学号*", "班级*", "姓名", "密码*", "电话号码", "QQ号码", "微信号", "地址"}
	for colIndex, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(colIndex+1, 1)
		f.SetCellValue("Sheet1", cell, header)
	}

	// 添加示例数据
	exampleData := [][]interface{}{
		{"202209120001", "计算机科学与技术1班", "张三", "123456", "13800138000", "123456789", "wx123456", "北京市海淀区"},
		{"202209120002", "计算机科学与技术1班", "李四", "123456", "13900139000", "987654321", "wx987654", "上海市浦东新区"},
	}

	for rowIndex, rowData := range exampleData {
		for colIndex, value := range rowData {
			cell, _ := excelize.CoordinatesToCellName(colIndex+1, rowIndex+2)
			f.SetCellValue("Sheet1", cell, value)
		}
	}

	// 调整列宽
	for i := range headers {
		colName, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth("Sheet1", colName, colName, 15)
	}

	// 设置文件名
	filename := "班级通讯录导入模板.xlsx"

	// 设置响应头，作为下载文件返回
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Transfer-Encoding", "binary")

	// 将文件写入响应
	err := f.Write(c.Writer)
	if err != nil {
		log.Println("生成Excel模板失败:", err)
		c.Status(http.StatusInternalServerError)
		return
	}
}
