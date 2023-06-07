#include <stdio.h>
#include "pcap.h"
#include <vector>
#include <time.h>

#pragma pack(1)            //字节对齐
typedef struct FrameHead_t //帧头
{
  byte Desmac[6]; //目的和源MAC
  byte Srcmac[6];
  WORD Frametype;
} FrameHead_t;

typedef struct IPHeader_t // IP头
{
  byte Ver_HLen;
  byte TOS;
  WORD TotalLen;
  WORD id;
  WORD Flag_Segment;
  byte TTL;
  byte Protocal;
  WORD Checksum;
  ULONG Srcip;
  ULONG Dstip;
} IPHeader_t;

typedef struct Data_t
{
  FrameHead_t FrameHeader;
  IPHeader_t IPHeader;
} Data_t;

#pragma pack() //恢复

void clear_all(std::vector<char *> devs, pcap_if_t *dev)
{
  devs.clear();
  pcap_freealldevs(dev);
}

int main()
{
  char errbuf[PCAP_ERRBUF_SIZE]; //存放错误信息的缓冲
  pcap_if_t *dev;

  /*
  列出网卡，参数：本机接口，无认证，接口指针，错误缓冲
  */
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &dev, errbuf) == -1)
  {
    printf("error:%s\n", errbuf);
    exit(-1);
  }
  printf("正在读取网卡列表...\n");
  std::vector<char *> devs; //存放名字
  for (int i = 1; dev != NULL; dev = dev->next, i++)
  {
    printf("No %d:%s\n", i, dev->description);
    printf("   Name: %s\n", dev->name);
    devs.push_back(dev->name);
  }

  /*
  打开网卡
  */
  printf("请输入要打开的网卡序号\n");
  int dev_num = 0;
  while (1)
  {
    scanf("%d", &dev_num);
    if (dev_num > devs.size() || dev_num < 1)
    {
      printf("范围错误，请重试!\n");
    }
    else
      break;
  }
  pcap_t *chosed_dev = pcap_open(devs[dev_num - 1], 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
  if (chosed_dev == NULL)
  {
    printf("打开网卡失败,error:%s\n", errbuf);
    clear_all(devs, dev);
    exit(-1);
  }
  else
  {
    printf("已打开网卡%d:%s\n", dev_num, devs[dev_num - 1]);
  }

  printf("\n正在监听...\n");

  /*
  抓包并分析
  */
  int res;
  pcap_pkthdr *header;    //指向数据包基本信息
  const u_char *pkt_data; //数据包
  time_t local_tv_sec;
  while ((res = pcap_next_ex(chosed_dev, &header, (const u_char **)&pkt_data)) >= 0)
  {
    if (res == 0)
    {
      //超时
      printf("超时1次\n");
      continue;
    }
    //时间戳
    local_tv_sec = header->ts.tv_sec;
    tm ltime;                           //日期格式结构体
    char timestr[64];                   //存放格式化的日期
    localtime_s(&ltime, &local_tv_sec); //
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
    printf("抓包成功@%s,数据包长度:%d\n", timestr, header->len);
    //接下来打印MAC和IP
    Data_t *IP_packet = (Data_t *)pkt_data;
    byte *desmacp = IP_packet->FrameHeader.Desmac;
    byte *srcmacp = IP_packet->FrameHeader.Srcmac;
    printf("Srcmac:");
    for (int i = 0; i < 6; i++)
    {
      printf("%02X", srcmacp[i]);
      if (i != 5)
        printf("-");
    }
    printf("\nDesmac:");
    for (int i = 0; i < 6; i++)
    {
      printf("%02X", desmacp[i]);
      if (i != 5)
        printf("-");
    }
    printf("\nFrameType:%d\n", IP_packet->FrameHeader.Frametype);

    long long int srcip=IP_packet->IPHeader.Srcip;
    long long int desip=IP_packet->IPHeader.Dstip;
    printf("srcip:");
    while(srcip>0){
      printf("%d",srcip%256);
      srcip/=256;
      if(srcip!=0)
      printf(".");
    }
    printf("\ndesip:");
    while(desip>0){
      printf("%d",desip%256);
      desip/=256;
      if(desip!=0)
      printf(".");
    }

    /*
    指示下一步
    */
    printf("\n输入1继续抓包,输入其他数字退出\n");
    int temp;
    scanf("%d", &temp);
    if (temp == 1)
      continue;
    else
      break;
  }

  if (res == -1)
  {
    printf("Error reading the packets: %s\n", pcap_geterr(chosed_dev));
    return -1;
  }

  printf("已退出!\n");
  clear_all(devs, dev);
}
