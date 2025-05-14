#ifndef ANTIVM_H
#define ANTIVM_H

bool DetectBySystemManufacturer();
bool DetectByBiosVendor();
bool DetectBySystemFamily();
bool DetectByProductName();
bool IsVboxVM();
bool IsVMwareVM();
bool IsMsHyperV();
void antiVm();

#endif