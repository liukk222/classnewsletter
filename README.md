如果你的数据库是root:123456@tcp(127.0.0.1:3306)且能在命令行登录mysql
则可以导入sql文件夹中的users.sql后打开数据库把以上所有文件放classnewsletter文件夹中在启动classnewsletter.exe运行在http://localhost:8080/login  查看项目
如果不是请修改数据库为root:123456@tcp(127.0.0.1:3306)或是根据你数据库信息对dao文件夹中dao.go的第33行"dsn := "root:123456@tcp(127.0.0.1:3306)/classnewsletter?charset=utf8mb4&parseTime=True&loc=Local""进行修改配置，准备golang环境重新编译
