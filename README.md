# AodFreeze
傲盾还原v3.1 修改自 [傲盾还原 By dbgger@gmail.com](https://code.google.com/p/diskflt) \
支持Windows7及以上版本的32位、64位系统 \
支持FAT、NTFS文件系统 \
自动保护MBR、GPT的分区表（保护盘分区表无法修改） \
防Ring3的穿透还原行为（SCSI Passthrough、IOCTL修改分区表）
支持驱动白名单、黑名单拦截（支持临时解除或开启驱动拦截），支持解冻空间，支持保护没有盘符的盘 \
**注意：开启驱动白名单后所有保护盘上原有的驱动会自动允许加载，不保护系统盘时不要开启驱动白名单** \
修复了会导致NTFS文件系统损坏的BUG
