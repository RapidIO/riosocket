RIOSocket-Basic Installation Instruction
========================================

1: Build and install kernel version >= 4.6 with following options and 
   configure the rapidio subsystem as mentioned in 
   Documentation/rapidio/rapidio.txt in kernel sources.

    CONFIG_RAPIDIO=m
    CONFIG_RAPIDIO_TSI721=m
    CONFIG_RAPIDIO_DISC_TIMEOUT=30
    CONFIG_RAPIDIO_ENABLE_RX_TX_PORTS=y
    CONFIG_RAPIDIO_DMA_ENGINE=y
    CONFIG_RAPIDIO_ENUM_BASIC=m
    CONFIG_RAPIDIO_TSI57X=m
    CONFIG_RAPIDIO_CPS_XX=m
    CONFIG_RAPIDIO_TSI568=m
    CONFIG_RAPIDIO_CPS_GEN2=m

   If using a standard distribution with kernel version >= 3.10 without
   wanting to update the default kernel, then enter the 
   <INST_DIR>/kernel-rapidio directory and issue the following commands:

   "make clean; make all; sudo make install""

   Follow configuration instructions described in kernel-rapidio/README file.

   Power cycle the entire cluster after installing the above modules.

2: Append the following to kernel command line in /boot/grub2/grub.cfg:
   "net.ifnames=0 biosdevname=0 memmap=256M\$1G"

   To automatically apply these command line options when updating the kernel
   edit GRUB_CMDLINE_LINUX configuration line in /etc/default/grub file:
   add "net.ifnames=0 biosdevname=0 memmap=256M\\\$1G". After saving the changes
   execute command "grub2-mkconfig -o /boot/grub2/grub.cfg". If required adjust
   this command for EFI boot.

3: Disable network manager by executing the following commands (depending on
   your Linux distribution):

   service NetworkManager stop
   chkconfig NetworkManager off

   or:

   systemctl stop NetworkManager.service
   systemctl disable NetworkManager.service

   Network interface configuration scripts should be adjusted accordingly.
   Network service has to be started and enabled as well.

4: Enter riosocket-basic directory and build the riosocket driver
   by typing "make clean; make all".
   Install the driver using "sudo make install" command.
   Edit /etc/modprobe.d/riosocket.conf file to provide parameters matching to
   reserved memory configuration set in step 2 above.

5: Enumerate the RIO network using one of methods that is applicable to your
   platform configuration. For example, use one of the following commands:
     echo -1 > /sys/bus/rapidio/scan, OR
     modprobe rio-scan scan=1

   Usually application level software provides set of scripts that simplify
   this task.

6: Confirm the nodes are detected by checking for devices in following path:

   ls /sys/bus/rapidio/devices

7: On each node:
   - load riosocket device driver using the following command:

      modprobe riosocket

   - enter the riosocket-basic directory and execute performance tuning script:
      ./perf.sh 

     If there is no irqbalance daemon running the perf.sh utility will report an 
     error which can be safely ignored.

8: After execution of step 7, a new network device named rsock0 will appear on
    executing ifconfig -a command. From this point onward, the rsock0 can be used
    as any other Ethernet interface. Assign IP address to rsock0 and ping to others
    nodes:

    ifconfig rsock0 10.12.10.1 up
    ping 10.12.10.2

9: To measure throughput, download/install iperf utility from 
    http://sourceforge.net/projects/iperf/ version 2.0.5 and execute the following 
    command:

    Server : iperf -s -fM
    Client : iperf -c <<Server IP>> -fM -i 1

    The exepected throughput for the first cut of the s/w is around 1.7 GBytes/sec for
     Gen2 5Gbps * 4 link. 
