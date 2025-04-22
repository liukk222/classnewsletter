package model

import (
	"gorm.io/gorm"
)

type User struct { //用户
	gorm.Model
	Studentid   string `json:"studentid"`   //学号
	Class       string `josn:"class"`       //班级
	Username    string `json:"username"`    //名字
	Password    string `json:"password"`    //密码
	Phonenumber string `json:"phonenumber"` //电话号码
	Qqnumber    string `json:"qqnumber"`    //qq号码
	Wxnumber    string `json:"wxnumber"`    //微信号
	Address     string `json:"address"`     //地址
}
