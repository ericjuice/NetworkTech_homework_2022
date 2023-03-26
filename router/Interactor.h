#ifndef _INTERACTOR_H
#define _INTERACTOR_H
#include "Router.h"
#include <stdio.h>
#include <string.h>

#define _INTERACTOR_H_INPUT_LEN 256 //最长输入字符串
#define _INTERACTOR_H_MAX_IP_NUM 3	//网卡最大IP数

class Interactor
{
public:
	char *tempargv[256];						 //------内部传参
	char input[_INTERACTOR_H_INPUT_LEN];		 // 输入字符串
	Router *router;								 // 路由器对象
	pcap_t *handle;								 // pcap_t
	IPAddr_t IPs[_INTERACTOR_H_MAX_IP_NUM];		 // 网卡绑定的IP
	IPAddr_t NetMasks[_INTERACTOR_H_MAX_IP_NUM]; // IP对应的子网掩码
public:											 //------用户交互
	pcap_t *selDev();							 // 打开设备，将设备绑定的IP保存到this->IPs，返回该设备打开的pcap_t*
	void saveIPs(pcap_if_t *);					 // 保存网卡的IP地址
	void initRouter(Router *);					 // 绑定IP，绑定MAC地址
	void printHelp();							 // 打印帮助
	void printHead();							 // 头信息
	char *getInput();							 // 获取输入，保存到this->input中，返回指向this->input的指针，若输入错误，则返回NULL
	int parseInput(char *);						 // 对输入命令进行词法分析
	char **split(int *, char *);				 // 分割输入的字符串
public:											 //自动功能
	Interactor();
	~Interactor();

	void work();					  // 顶层接口，进行工作
	int addRecord(int, char **);	  // 返回布尔值，若输入格式不正确，返回-1
	int delRecord(int, char **);	  // 返回布尔值，若输入格式不正确，返回-1
	int printSomething(int, char **); // 返回布尔值，若输入格式不正确，返回-1
};

#endif