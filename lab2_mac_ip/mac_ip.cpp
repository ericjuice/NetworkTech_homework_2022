#include <stdio.h>
#include "pcap.h"
#include <vector>
#include <time.h>
#include <string>

#pragma pack(1)            //字节对齐
typedef struct FrameHead_t //帧头
{
    byte Desmac[6]; //目的和源MAC
    byte Srcmac[6];
    WORD Frametype;
} FrameHead_t; // 14b

typedef struct ARPFrame_t
{
    FrameHead_t FrameHead;
    WORD HardwareType; // 2b
    WORD ProtocolType;
    byte Hlen;
    byte Plen;
    WORD Operation;
    byte SendHa[6];
    DWORD SendIP;
    byte RecvHa[6];
    DWORD RecvIP;
} ARPFrame_t;

#pragma pack() //恢复

struct net_dev //保存我获得的网卡的信息
{
    char *name;
    byte mac[6];
    //下面这里是从源码cv的，虽然很蠢，但是能跑...
    struct sockaddr *addr;      /* ipaddress */
    struct sockaddr *netmask;   /* netmask for that address */
    struct sockaddr *broadaddr; /* broadcast address for that address */
    struct sockaddr *dstaddr;   /* P2P destination address for that address */
};

std::vector<net_dev> devs;     //存放网卡信息
char errbuf[PCAP_ERRBUF_SIZE]; //存放错误信息的缓冲
pcap_if_t *dev;                //存网卡信息

void clear_all()
{
    devs.clear();
    pcap_freealldevs(dev);
}

bool send_arp(pcap_t *chosed_dev, DWORD desip, byte srcmac[6], DWORD srcip);

bool get_mac(byte devmac[6], pcap_t *chosed_dev, int dev_num); // devmac保存mac，chosed_dev为要打开的网卡,dev_num保存信息

bool wait_arp(pcap_t *choseddev, DWORD targetip);

int main()
{
    //列出网卡，参数：本机接口，无认证，接口指针，错误缓冲
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &dev, errbuf) == -1)
    {
        printf("error:%s\n", errbuf);
        exit(-1);
    }
    printf("正在读取网卡列表...\n");
    for (int i = 1; dev != NULL; dev = dev->next, i++)
    {
        pcap_addr_t *a; //临时的地址指针
        printf("No %d:%s\n", i, dev->description);
        printf("   Name: %s\n", dev->name);
        net_dev newdev;
        newdev.name = dev->name;
        a = dev->addresses;
        if (a != nullptr)
        {
            newdev.addr = a->addr; // ip info
            newdev.netmask = a->netmask;
            newdev.broadaddr = a->broadaddr;
            newdev.dstaddr = a->dstaddr;
        }
        devs.push_back(newdev);
    }

    //打开网卡
    printf("请输入要打开的网卡序号\n");
    int dev_num = 0;
    scanf("%d", &dev_num);

    pcap_t *chosed_dev = pcap_open(devs[dev_num - 1].name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (chosed_dev == NULL)
    {
        printf("打开网卡失败,error:%s\n", errbuf);
        clear_all();
        exit(-1);
    }
    else
        printf("已打开网卡%d:%s\n", dev_num, devs[dev_num - 1].name);

    if (pcap_datalink(chosed_dev) != DLT_EN10MB)
    {
        printf("不是以太网捏\n");
        clear_all();
        return -1;
    }

    //过滤
    printf("设置arp过滤器...\n");
    struct bpf_program fcode;
    char packet_filter[] = "ether proto \\arp";
    if (pcap_compile(chosed_dev, &fcode, packet_filter, 1, ((struct sockaddr_in *)devs[dev_num - 1].netmask)->sin_addr.S_un.S_addr) < 0)
    {
        printf("编译过滤器失败\n");
        clear_all();
        return -1;
    }
    if (pcap_setfilter(chosed_dev, &fcode) < 0)
    {
        fprintf(stderr, "\n设置过滤失败.\n");
        clear_all();
        return -1;
    }

    printf("请稍等,正在获取这块网卡对应mac...\n");
    get_mac(devs[dev_num - 1].mac, chosed_dev, dev_num); //用arp获取自己的mac
    while (true)
    {
        printf("请输入要发送arp的ip\n");
        char ipstr[20];
        scanf("%s", ipstr);
        DWORD ip_tosd = inet_addr(ipstr);
        //这里操作有点蠢，一大串，但是能跑，算了
        send_arp(chosed_dev, ip_tosd, devs[dev_num - 1].mac, ((struct sockaddr_in *)devs[dev_num - 1].addr)->sin_addr.S_un.S_addr);
        printf("\n已发送,正在等待回应...\n");
        wait_arp(chosed_dev, ip_tosd); //等我抓到目标的arp包

        //指示下一步
        printf("\n输入1继续,输入其他数字退出\n");
        int temp;
        scanf("%d", &temp);
        if (temp == 1)
            continue;
        else
            break;
    }
    printf("已退出!\n");
    clear_all();
}

bool wait_arp(pcap *chosed_dev, DWORD targetip)
{
    //抓包并分析
    int res;
    pcap_pkthdr *header;    //指向数据包基本信息
    const u_char *pkt_data; //数据包
    time_t local_tv_sec;
    while ((res = pcap_next_ex(chosed_dev, &header, (const u_char **)&pkt_data)) >= 0)
    {
        if (res == 0)
        {
            printf("超时1秒\n");
            continue;
        }

        //接下来打印MAC
        ARPFrame_t *arp_packet = (ARPFrame_t *)pkt_data;
        if (arp_packet->Operation == htons(0x0002) // ARP_REPLY
            && arp_packet->SendIP == targetip)     //发送的应该是你
        {
            local_tv_sec = header->ts.tv_sec;   //时间戳
            tm ltime;                           //日期格式结构体
            char timestr[64];                   //存放格式化的日期
            localtime_s(&ltime, &local_tv_sec); //
            strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
            printf("抓包成功@%s,数据包长度:%d\n", timestr, header->len);
            byte *srcmacp = arp_packet->SendHa;
            printf("对方mac:");
            for (int i = 0; i < 6; i++)
            {
                printf("%02X", srcmacp[i]);
                if (i != 5)
                    printf("-");
            }
            break;
        }
        else
            continue;
    }
    return true;
}

bool send_arp(pcap_t *chosed_dev, DWORD desip, byte srcmac[6], DWORD srcip)
{
    ARPFrame_t arpf;
    // Arphead
    byte broadcasta[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; //广播
    memcpy(arpf.FrameHead.Desmac, broadcasta, 6);              //设置帧的mac和类型
    memcpy(arpf.FrameHead.Srcmac, srcmac, 6);
    arpf.FrameHead.Frametype = htons(0x0806); // arp

    arpf.HardwareType = htons(0x0001); // Ethernet
    arpf.ProtocolType = htons(0x0800); // ip
    arpf.Hlen = 6;
    arpf.Plen = 4;
    arpf.Operation = htons(0x0001); // arp

    memcpy(arpf.SendHa, srcmac, 6); //源mac/ip
    arpf.SendIP = srcip;
    memset(arpf.RecvHa, '\0', 6); //目的mac置0
    arpf.RecvIP = desip;
    if (pcap_sendpacket(chosed_dev, (u_char *)&arpf, sizeof(arpf)) == -1)
    {
        printf("send arp error\n");
        return -1;
    }
    else
    {
        printf("send arp success\n");
    }
    return true;
}

bool get_mac(byte devmac[6], pcap_t *chosed_dev, int dev_num) // devmac保存mac，chosed_dev为要打开的网卡,dev_num保存信息
{
    byte srcmac[6] = {1, 1, 1, 1, 1, 1};                                                //芝士假冒的全1的mac
    DWORD desip = ((struct sockaddr_in *)devs[dev_num - 1].addr)->sin_addr.S_un.S_addr; // 网卡地址
    DWORD srcip = 1869573999;                                                           //芝士假冒的16进制的111.111.111.111
    send_arp(chosed_dev, desip, srcmac, srcip);

    int res;
    pcap_pkthdr *header;    //指向数据包基本信息
    const u_char *pkt_data; //数据包
    while ((res = pcap_next_ex(chosed_dev, &header, (const u_char **)&pkt_data)) >= 0)
    {
        if (res == 0) // 超时1次
            continue;
        //获取MAC
        ARPFrame_t *arp_packet = (ARPFrame_t *)pkt_data;
        if (arp_packet->RecvIP == srcip               //接收的是我
            && arp_packet->Operation == htons(0x0002) // ARP_REPLY
            && arp_packet->SendIP == desip)           //发送的应该是你
        {
            memcpy(devs[dev_num - 1].mac, arp_packet->SendHa, 6); //把获得的mac赋给这个dev
            printf("获取成功啦,mac:");
            printf("mac:");
            for (int i = 0; i < 6; i++)
            {
                printf("%02X", arp_packet->SendHa[i]);
                if (i != 5)
                    printf("-");
            }
            break;
        }
        else
            continue;
    }
    if (res == -1)
        printf("获取mac失败\n");
    return true;
}