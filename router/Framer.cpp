#include "Framer.h"

int bitCount(uint32_t n){
    int result = 0;
    for (result = 0; n; result = result + 1){
        n = n & (n - 1); // 清除最低位的1
    }
    return result;
}

void copyMAC(MACAddr_t* DesMAC, MACAddr_t* SrcMAC) {
    memcpy(DesMAC,SrcMAC,sizeof(*SrcMAC));
    // for (int i = 0; i < 6; i = i + 1) {
    //     DesMAC->MAC[i] = SrcMAC->MAC[i];
    // }
}

uint16_t computeCheckSum(u_char* _gram_, int _size_) {
    uint32_t checkSum = 0;
    int i = 0;
    for (i = 0; i < _size_ - 1; i = i + 2) {
        checkSum = ntohs(*(uint16_t*)(_gram_ + i)) + checkSum;
        while (checkSum / 0x10000 != 0) {
            checkSum = (checkSum / 0x10000) + (checkSum % 0x10000);
        }
    }
    if (i < _size_) {
        char tempA[2];
        tempA[0] = _gram_[i];
        tempA[1] = 0;
        checkSum = *(uint16_t*)(tempA)+checkSum;
        while (checkSum / 0x10000 != 0) {
            checkSum = (checkSum / 0x10000) + (checkSum % 0x10000);
        }
    }
    return htons((uint16_t)(checkSum % 0x10000));
}

void Convert_string_to_IP(u_char* __IP__, char* __string__) {
    int i = 0;
    int j = 0;
    u_char temResult = 0;
    while (__string__[i] != 0) {
        if (__string__[i] == '.') {
            __IP__[j] = temResult;
            j = j + 1;
            temResult = 0;
        }
        else {
            temResult = temResult * 10 + __string__[i] - 48;
        }
        i = i + 1;
    }
    __IP__[3] = temResult;
    return;
}