package dao

import (
	"classnewsletter/model"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Manager interface {
	//用户操作
	Redirect(user *model.User)                                                 //创建用户
	Login(studentid string) model.User                                         //登录用户
	DeleteUser(user *model.User)                                               //用户删除
	GetAllUser() ([]model.User, error)                                         //获得所有用户
	UpdateUser(user *model.User)                                               //用户更新
	GetIdUser(userid uint) *model.User                                         //返回指定用户
	GetClassAllUser(class string) ([]model.User, error)                        //返回班级用户
	GetClassAndNanmeemAllUser(class string, name string) ([]model.User, error) //返回指定名字用户
	GetStudentidAndClassUser(studentid string, class string) model.User        //返回指定学号班级用户
	GetNameAllUser(name string) ([]model.User, error)                          //获取名字所有用户
}

type manager struct {
	db *gorm.DB
}

var Mgr Manager

// 连接mysql数据库
func init() {
	dsn := "root:123456@tcp(127.0.0.1:3306)/classnewsletter?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to init db:", err)
	}
	Mgr = &manager{db: db}
	db.AutoMigrate(&model.User{})
}

func (mgr *manager) Redirect(user *model.User) { //创建用户
	mgr.db.Create(user)
}
func (mgr *manager) Login(studentid string) model.User { //登录用户
	var user model.User
	mgr.db.Where("studentid=?", studentid).First(&user)
	return user
}

func (mgr *manager) DeleteUser(user *model.User) { //用户删除
	mgr.db.Unscoped().Delete(&user)
}

func (mgr *manager) GetAllUser() ([]model.User, error) { //获取所有用户
	var user []model.User
	err := mgr.db.Find(&user).Error
	if err != nil {
		return nil, err
	} else {
		return user, nil

	}
}

func (mgr *manager) UpdateUser(user *model.User) { //更新用户
	mgr.db.Save(user)
}

func (mgr *manager) GetIdUser(userid uint) *model.User { //返回指定id用户
	var user model.User
	mgr.db.First(&user, userid)
	return &user
}

func (mgr *manager) GetClassAllUser(class string) ([]model.User, error) { //获取班级所有用户
	var user []model.User
	err := mgr.db.Where("class = ?", class).Find(&user).Error
	if err != nil {
		return nil, err
	} else {
		return user, nil

	}
}

func (mgr *manager) GetClassAndNanmeemAllUser(class string, name string) ([]model.User, error) { //获取班级所有用户
	var user []model.User
	err := mgr.db.Where("class = ?", class).Where("username = ?", name).Find(&user).Error
	if err != nil {
		return nil, err
	} else {
		return user, nil

	}
}

func (mgr *manager) GetStudentidAndClassUser(studentid string, class string) model.User { //返回指定学号班级用户
	var user model.User
	mgr.db.Where("studentid=?", studentid).Where("class=?", class).First(&user)
	return user
}

func (mgr *manager) GetNameAllUser(name string) ([]model.User, error) { //获取名字所有用户
	var user []model.User
	err := mgr.db.Where("username = ?", name).Find(&user).Error
	if err != nil {
		return nil, err
	} else {
		return user, nil

	}
}
