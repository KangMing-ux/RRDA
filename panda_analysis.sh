#!/bin/bash

good_luck(){
    echo  -e '\033[36m         ###   ##    ##   ##        #    #  #   ##  # #\033[0m'
    echo  -e '\033[36m        #     #  #  #  #  #  #      #    #  #  #    ## \033[0m'
    echo  -e '\033[36m        # ##  #  #  #  #  #  #      #    #  #  #    ## \033[0m'
    echo  -e '\033[36m         # #   ##    ##   ##        ###   ##    ##  # #\033[0m'
    echo ''
}

if [[ $# -lt 7 || $# -gt 9 ]]
then
    echo 'usage: sudo ./panda_analysis.sh <mode> <rr_name> <arch> <memory_size> <os> <os_version> <qcow_path> <network_if> <disk_if>'
    echo ''
    echo 'mode : syscall | memory'
    echo ''
    echo 'rr_name: record_replay name'
    echo ''
    echo 'arch : i386 | x86_64'
    echo ''
    echo 'memory_size: NG | NM (N is interger)'
    echo ''
    echo 'os: linux | windows'
    echo ''
    echo "os_version: see PANDA document for details...(Panda's os_version=os + my os_version)"
    echo ''
    echo 'network_if: rtl8139 | e1000 | ...(when the default config for network interface(rtl8139) occur error, you need to tell PyPanda the correct network interface , same as the network interface when record)'
    echo ''
    echo 'disk_if: scsi | ide | ...(When only specifying the qcow2 path PyPanda cannot run correctly, you need to tell it the correct disk interface qcow2 use, same as the disk interface when record)'
else
    rr_log=$2'-rr-nondet.log'
    if [ -e $rr_log ]
    then
        echo -e "\033[32mfound ${rr_log} in .\033[0m"
    else
        mv log/$rr_log .
        echo -e "\033[32mfound ${rr_log} in ./log\033[0m"
    fi
    echo ''
    rr_snp=$2'-rr-snp'
    if [ -e $rr_snp ]
    then
        echo -e "\033[32mfound ${rr_snp} in .\033[0m"
    else
        mv snp/$rr_snp .
        echo -e "\033[32mfound ${rr_snp} in ./snp\033[0m"
    fi
    echo ''
    cp code/*py .
    if [ $1 = 'syscall' ]
    then
        if [ $5 = 'linux' ]
        then
            if [ $3 = 'i386' ]
            then
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-32-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-32-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-32-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-32-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-32-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-32-"$6 $5 $7 $8 $9
                    fi
                fi
            else
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-64-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-64-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-64-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-64-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_syscalls2_linux.py $2 $3 $4 $5-64-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_linux.py $2 $3 $4 $5"-64-"$6 $5 $7 $8 $9
                    fi
                fi
            fi
        elif [ $5 = 'windows' ]
        then
            if [ $3 = 'i386' ]
            then
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_syscalls2_win32.py $2 $3 $4 $5-32-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_win32.py $2 $3 $4 $5"-32-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_syscalls2_win32.py $2 $3 $4 $5-32-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_win32.py $2 $3 $4 $5"-32-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_syscalls2_win32.py $2 $3 $4 $5-32-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_syscalls2_win32.py $2 $3 $4 $5"-32-"$6 $5 $7 $8 $9
                    fi
                fi
            else
                echo 'unsupported arch!'
            fi
        else
            echo 'unsupported os!'
        fi
    elif [ $1 = 'memory' ]
    then
        if [ $5 = 'linux' ]
        then
            if [ $3 = 'i386' ]
            then
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-32-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-32-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-32-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-32-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-32-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-32-"$6 $5 $7 $8 $9
                    fi
                fi
            else
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-64-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-64-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-64-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-64-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_check_linux.py $2 $3 $4 $5-64-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_linux.py $2 $3 $4 $5"-64-"$6 $5 $7 $8 $9
                    fi
                fi
            fi
        elif [ $5 = 'windows' ]
        then
            if [ $3 = 'i386' ]
            then
                if [ $# -eq 7 ]
                then
                    echo "python3 rr_check_win32.py $2 $3 $4 $5-32-$6 $5 $7"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_win32.py $2 $3 $4 $5"-32-"$6 $5 $7
                    fi
                elif [ $# -eq 8 ]
                then
                    echo "python3 rr_check_win32.py $2 $3 $4 $5-32-$6 $5 $7 $8"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_win32.py $2 $3 $4 $5"-32-"$6 $5 $7 $8
                    fi
                else
                    echo "python3 rr_check_win32.py $2 $3 $4 $5-32-$6 $5 $7 $8 $9"
                    echo -ne '\033[31m[check]\033[0m'
                    echo -ne '\033[33m Is this what you want to run[y/n]:\033[0m'
                    read yn
                    if [ $yn = 'y' ]
                    then
                        good_luck
                        python3 rr_check_win32.py $2 $3 $4 $5"-32-"$6 $5 $7 $8 $9
                    fi
                fi
            else
                echo 'unsupported arch!'
            fi
        else
            echo 'unsupported os!'
        fi
    fi
    mv $rr_log log/
    mv $rr_snp snp/
    rm -f *py
    if [ -e $2'_node.set' ]
    then
        mv $2'_node.set' output/
    fi
    if [ -e $2'_edge.list' ]
    then
        mv $2'_edge.list' output/
    fi
fi

# sudo ./panda_analysis.sh syscall rr_tgt2_electricslide i386 1G linux redhat:2.4.20-generic /var/lib/libvirt/images/TGT_2.qcow2 e1000
# sudo ./panda_analysis.sh syscall rr_tgt2_embersnout i386 1G linux redhat:2.4.20-generic /var/lib/libvirt/images/TGT_2.qcow2 e1000
# sudo ./panda_analysis.sh syscall rr_tgt3_evenlesson i386 1G linux redhat:2.4.2-2-generic /var/lib/libvirt/images/TGT_3.qcow2 rtl8139 scsi
# sudo ./panda_analysis.sh syscall rr_tgt3_earlyshovel i386 1G linux redhat:2.4.2-2-generic /var/lib/libvirt/images/TGT_3.qcow2 rtl8139 scsi
# sudo ./panda_analysis.sh syscall rr_tgt3_telex i386 1G linux redhat:2.4.2-2-generic /var/lib/libvirt/images/TGT_3.qcow2 rtl8139 scsi
# sudo ./panda_analysis.sh syscall rr_tgt3_wuftpd i386 1G linux redhat:2.4.2-2-generic /var/lib/libvirt/images/TGT_3.qcow2 rtl8139 scsi
# sudo ./panda_analysis.sh syscall i386 2G linux-64-ubuntu:5.4.0-42-generic /var/lib/libvirt/images/TGT_8.qcow2 linux vmware_TGT8_phuip-fpizdam
