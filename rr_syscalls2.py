from enum import Enum

# include/linux/net.h (get linux kernel code from https://kernel.org/)
SOCKET_CALL=(None, None, None,'connect', None, 'accept', None, None, None, 'send', 'recv', 'sendto', 'recvfrom', None, None, None, 'sendmsg', 'recvmsg')

class ADDRESS_FAMILY(Enum):
    AF_UNIX=1
    AF_INET=2

# (syscall_name, node_idx, node_idx)
last_syscall_event=None

# (asid, sockfd) => (ip, port)/unix_path
sockfdinfo=dict()

# (asid, shmaddr) => shmid | (asid, mapaddr) => filename
shminfo=dict()

# asid => pwd
pwdinfo=dict()
